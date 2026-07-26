-- Supersedes the 2026-07-19-000000 migration of the same name, which was edited
-- in place twice after it had already been applied. diesel_migrations records
-- only (version, run_on) with no checksum, so an edited migration never re-runs:
-- any database that took an earlier version would have kept that schema forever,
-- silently diverging from a freshly migrated one. Reissuing under a new version
-- is the only change that reaches both. DROP first so this is reachable from
-- either starting state; the table holds only regenerable token digests.
DROP TABLE IF EXISTS scim_api_key;

-- org_uuid is VARCHAR(40) to match organizations.uuid exactly (VARCHAR(40) here
-- and on mysql). It was CHAR(36), which was wrong twice over: an org uuid of
-- 37-40 characters is legal in the parent table and inserts fine on mysql and
-- sqlite but fails here with "value too long for type character(36)", making the
-- SCIM key un-mintable for that organization on one backend only; and bpchar
-- blank-pads shorter values on storage and returns the padding, so a comparison
-- in Rust against an unpadded value would silently stop matching.
CREATE TABLE scim_api_key (
	uuid            CHAR(36) NOT NULL PRIMARY KEY,
	org_uuid        VARCHAR(40) NOT NULL UNIQUE REFERENCES organizations(uuid) ON DELETE CASCADE,
	key_hash        TEXT NOT NULL,
	enabled         BOOLEAN NOT NULL DEFAULT true,
	created_at      TIMESTAMP NOT NULL,
	revision_date   TIMESTAMP NOT NULL
);
