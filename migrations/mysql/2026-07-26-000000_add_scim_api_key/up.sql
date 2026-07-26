-- Supersedes the 2026-07-19-000000 migration of the same name, which was edited
-- in place twice after it had already been applied. diesel_migrations records
-- only (version, run_on) with no checksum, so an edited migration never re-runs:
-- any database that took an earlier version would have kept that schema forever,
-- silently diverging from a freshly migrated one. Reissuing under a new version
-- is the only change that reaches both. DROP first so this is reachable from
-- either starting state; the table holds only regenerable token digests.
DROP TABLE IF EXISTS scim_api_key;

-- The FOREIGN KEY must be a table-level clause: MySQL silently ignores inline
-- column-level REFERENCES, so an inline one would create no real constraint.
--
-- org_uuid is VARCHAR(40) to match organizations.uuid exactly, which is
-- VARCHAR(40) on BOTH mysql and postgresql. An InnoDB foreign key additionally
-- requires the child column to match the parent's type, so a narrower one would
-- be rejected outright here rather than failing later on a long value.
CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        VARCHAR(40) NOT NULL UNIQUE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT TRUE,
	created_at      DATETIME NOT NULL,
	revision_date   DATETIME NOT NULL,
	FOREIGN KEY(org_uuid) REFERENCES organizations(uuid) ON DELETE CASCADE
);
