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

**Deploying the SCIM branch is additive on a fresh install, and destructive only
if you already ran an earlier build of that branch.** Which case you are in, and
what the second one costs, is in
[This upgrade specifically](#this-upgrade-specifically-deploying-the-scim-branch)
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

### Picking the window

- Business hours are the thing to avoid, not "daylight". Pick the window against
  your own users' working day.
- **Confirm the server's timezone before you schedule anything.** Cron
  expressions and scheduled jobs in `.env` are evaluated in the server's
  timezone, not yours, and the two are frequently different. If either observes
  daylight saving, check which offset applies on the date you have chosen rather
  than the one in effect when you wrote the schedule.
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

## This upgrade specifically: deploying the SCIM branch

Meaning the upgrade that first brings this fork's SCIM feature into an existing
deployment.

Two clarifications, because both numbers are easy to misread:

- **There is no SCIM release.** The feature lives on `feature/scim-v2` and has
  never been tagged or released; the changelog entry is `Unreleased` for that
  reason. Deploying it today means building from the branch. It becomes a
  release only if and when it merges to `main` and is tagged.
- **`v2` is the protocol, not a version of this feature.** This server speaks
  **SCIM 2.0** (RFC 7643 / RFC 7644) and nothing else, at `/scim/v2/<org_id>`.
  It has no relationship to the superseded SCIM 1.1 protocol.

**Which case are you in?**

- **Installing SCIM for the first time: no window, nothing to plan.** The
  migrations are effectively additive against a database that has never had a
  `scim_api_key` table - the `DROP TABLE IF EXISTS` is a no-op on an empty
  schema - and there are no SCIM tokens yet to invalidate. This is almost
  certainly you. Skip ahead to [Pre-flight checklist](#pre-flight-checklist);
  the `Sequence` below is not for you.
- **You already ran an earlier build of `feature/scim-v2`: Class B, take a
  window.** This is the only case the rest of this section is about, and it
  exists because the branch's first migration was edited in place before the
  branch was published. If you have never deployed this branch, that history
  cannot affect you.

For the second case only, two things make it destructive:

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

Five companion migrations follow it:

| Version | What it does |
|---|---|
| `2026-07-26-000001_unique_users_organizations_external_id` | Clears duplicate `external_id` values on `users_organizations`, then makes `(org_uuid, external_id)` UNIQUE |
| `2026-07-26-000002_unique_groups_external_id` | The same for `groups` |
| `2026-07-26-000003_add_scim_api_key_last_used` | `scim_api_key.last_used_at`, nullable. Additive |
| `2026-07-26-000004_add_users_organizations_paging_index` | `(org_uuid, uuid)` on `users_organizations`. Additive |
| `2026-07-26-000005_add_groups_paging_index` | `(organizations_uuid, uuid)` on `groups`. Additive |

### The two that are NOT additive - read this before upgrading

> [!WARNING]
> `000001` and `000002` make `external_id` UNIQUE per organization, and **each
> one clears data to get there**. They are the only migrations on this branch
> that destroy anything, and they run before the process serves, so there is no
> opportunity to intervene once it starts.

**What gets cleared.** Where two rows in one organization claim the same
directory object, one keeps its correlation key and the rest are set to NULL.
Nothing else is touched: no membership, no `akey`, no group, no access. A
cleared correlation is re-established by the next sync for whichever row the
directory still sends.

This is not hypothetical on an upgrade. Upstream's own Directory Connector
import writes `external_id` with no uniqueness handling at all, so an existing
deployment can already be holding duplicates.

**Which row survives is arbitrary.** The keeper is `MIN(uuid)`, and uuids are
random v4 values with no time component, so it is *not* "the oldest". There is
no better option on `users_organizations`, which carries no creation timestamp.

**Three dialect differences worth knowing before you upgrade:**

- **MySQL** enforces uniqueness over the first **150 characters** only (the
  column is TEXT and MySQL cannot index it without a prefix). Two externalIds
  differing only after character 150 collide there and not elsewhere.
- **MySQL** also compares case-insensitively under its default `utf8mb4`
  collation, so `ABC` and `abc` are one key there and two on SQLite and
  PostgreSQL. One of a case-differing pair will have its correlation cleared.
- **PostgreSQL** additionally clears any `external_id` longer than 2000 bytes.
  A plain btree entry caps at roughly 2704 bytes, and a single over-long row
  would make the index creation fail outright - which is a server that will not
  start. SCIM never writes one that long (the cap is 300 characters); the
  Directory Connector import applies no length check at all.

**Check first, and take a backup.** This tells you whether your install is
affected at all - most are not:

```sql
-- Any row returned means a correlation key will be cleared.
SELECT org_uuid, external_id, COUNT(*)
FROM users_organizations
WHERE external_id IS NOT NULL
GROUP BY org_uuid, external_id HAVING COUNT(*) > 1;

-- MySQL only: the index enforces a 150-character prefix, so check that too.
SELECT org_uuid, LEFT(external_id, 150), COUNT(*)
FROM users_organizations
WHERE external_id IS NOT NULL
GROUP BY org_uuid, LEFT(external_id, 150) HAVING COUNT(*) > 1;
```

Run the same two against `groups` with `organizations_uuid` in place of
`org_uuid`.

**Rolling back does not restore what was cleared.** The `down.sql` files drop
the indexes, which is all a rollback can honestly do - the cleared values are
gone, and the next sync re-establishes them.

**Each index gets its own migration, one `CREATE INDEX` per file.** That is not
tidiness, it is the only retryable shape on MySQL. MySQL DDL is not
transactional and MySQL supports neither `CREATE INDEX IF NOT EXISTS` nor
`DROP INDEX IF EXISTS`, so when two index statements shared one migration a
failure on the second left the first committed while the migration went
unrecorded - and every retry then died on `ERROR 1061 Duplicate key name`,
making the database unmigratable. Since migrations run before the process
serves, that is a server that permanently refuses to start. If you add a SCIM
index later, keep the one-statement-per-migration rule.

**Never edit a migration that has shipped.** Diesel records the migration
VERSION - the timestamp prefix - in `__diesel_schema_migrations`, and will never
re-run a version it has already applied. Editing a released migration is
therefore not a change: it is a silent no-op on every database that already ran
it, and a different schema on every database that has not, with nothing to
detect the divergence. Every change to a shipped migration arrives as a NEW
migration, including one that only looks cosmetic - the file is the record of
what that version did.

The exception is a migration that has never been released, which can be edited or
collapsed freely. The two `external_id` migrations above were collapsed exactly
that way: an earlier arrangement created a non-unique index, added a UNIQUE one
on the identical key in a second migration, and dropped the first in a third.
Six migrations became two while nothing had been deployed. That window closes the
moment this branch merges.

One consequence for developers: collapsing invalidates existing development
databases. The recorded version is already applied, so the rewritten file never
runs and you silently end up without the constraint. Recreate the database. The
SCIM suite fails loudly in that state rather than passing quietly, which is the
only reason collapsing is tolerable at all.

The two paging indexes back the `ORDER BY uuid` that the list endpoints depend
on for a stable page order. Without them the database sorts the organization's
entire membership once per page, and a full Entra sync of a large org issues
hundreds of pages per cycle.

### Sequence

Only for a deployment that already ran an earlier build of this branch. On a
first install there is nothing here to do.

```bash
# 1. Notify users. Impact: vault reads keep working offline; sync pauses.
# 2. Back up and PROVE the restore (see pre-flight above).
# 3. Stop the service.
# 4. Deploy the new image; migrations run at startup.
# 5. Verify:
curl -fsS https://your.domain/alive

# 6. Re-mint each organization's SCIM token - the old ones no longer exist.
#    Requires an OWNER session (not merely an admin) on the current branch.
#    Full sequence: docs/scim/setup.md, "Part B - Generate the organization's
#    SCIM token".

# 7. Paste each new token into the matching Entra enterprise application
#    (Provisioning -> Admin Credentials -> Secret Token), then Test Connection.

# 8. Let Entra run one full sync cycle and check the provisioning log before
#    declaring the upgrade done.
```

As above: on a first install none of this costs you anything, and the sequence
below is only for a deployment that already ran an earlier build of this branch.

### Note if you were running an earlier build of this branch

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
