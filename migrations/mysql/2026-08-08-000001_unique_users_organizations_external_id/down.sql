-- mysql supports neither DROP INDEX ... IF EXISTS nor a conditional form, so
-- this is unguarded. diesel only runs down for a migration it recorded as
-- applied, so the index exists whenever this runs.
--
-- The dedup in up.sql is not reversible: the cleared external_ids are gone and
-- the next IdP sync re-establishes them. Dropping the index restores the old
-- unenforced behaviour, which is all a rollback can honestly do.
DROP INDEX idx_users_organizations_org_external_id_unique ON users_organizations;
