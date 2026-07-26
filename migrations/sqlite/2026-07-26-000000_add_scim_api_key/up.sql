-- Supersedes the 2026-07-19-000000 migration of the same name, which was edited
-- in place twice after it had already been applied. diesel_migrations records
-- only (version, run_on) with no checksum, so an edited migration never re-runs:
-- any database that took an earlier version would have kept that schema forever,
-- silently diverging from a freshly migrated one with no error and no way to
-- notice. Reissuing under a new version is the only change that reaches both.
--
-- DROP first so this is reachable from either starting state. The table holds
-- only SCIM bearer-token digests, which are regenerable - an operator who minted
-- a token on a pre-release build re-mints it - and nothing references the table.
DROP TABLE IF EXISTS scim_api_key;

-- ON DELETE CASCADE is declared for parity with the mysql and postgresql
-- migrations, but it does NOT fire on sqlite: nothing in this tree ever issues
-- `PRAGMA foreign_keys = ON` on a pooled runtime connection (the pool's
-- on_acquire hook runs DATABASE_CONN_INIT, which sets only busy_timeout and
-- synchronous), and sqlite defaults the pragma off per connection. Deleting an
-- organization therefore relies on `Organization::delete` calling
-- `ScimApiKey::delete_all_by_organization` explicitly, which is what actually
-- keeps all three backends consistent. Do not drop that call on the strength of
-- this clause.
CREATE TABLE scim_api_key (
	uuid            TEXT NOT NULL PRIMARY KEY,
	org_uuid        TEXT NOT NULL UNIQUE REFERENCES organizations(uuid) ON DELETE CASCADE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT 1,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL
);
