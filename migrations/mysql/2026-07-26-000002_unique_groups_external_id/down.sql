-- The dedup in up.sql is not reversible: the cleared external_ids are gone and
-- the next IdP sync re-establishes them. Dropping the index restores the old
-- unenforced behaviour, which is all a rollback can honestly do.
--
-- Unguarded for the same reason as its sibling; `groups` needs backticks.
DROP INDEX idx_groups_org_external_id_unique ON `groups`;
