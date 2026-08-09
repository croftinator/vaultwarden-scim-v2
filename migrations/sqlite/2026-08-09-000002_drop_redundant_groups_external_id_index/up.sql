-- See the sibling migration for users_organizations: 2026-08-08-000002 created
-- a UNIQUE index on the same key this one covers, so this is redundant.
DROP INDEX IF EXISTS idx_groups_org_external_id;
