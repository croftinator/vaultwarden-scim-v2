-- Make the SCIM correlation key actually unique per organization.
--
-- Until now uniqueness was enforced only in application code: a
-- find_by_external_id_and_org lookup followed by a write, with nothing between
-- them. Two concurrent requests could both pass the check and commit, after
-- which find_by_external_id_and_org resolves via .first() and a later sync binds
-- to an arbitrary one of the duplicates - so the IdP can update or deprovision
-- the wrong member. The index below turns that invariant into one the database
-- keeps.
--
-- NULL external_ids stay duplicable, which is what we want: most memberships
-- have never been correlated to a directory object, and standard UNIQUE
-- semantics treat NULLs as distinct on postgresql.
--
-- TWO statements here, unlike the plain index migrations that ship exactly one.
-- That rule exists because MySQL DDL is not transactional, so a second failing
-- CREATE INDEX left the first committed and unrecorded, and every retry then
-- died on "Duplicate key name". The pair below is safely retryable for a
-- different reason: the first statement is idempotent (running it twice clears
-- nothing new) and the second creates nothing until it succeeds, so a failure
-- leaves a state the retry handles cleanly.

-- Any pre-existing duplicates must be resolved BEFORE the unique index is
-- created, or the CREATE fails - and because migrations run at pool
-- construction, before Rocket listens, a failing migration is a server that
-- permanently refuses to start. Keeping ONE row's correlation and clearing the
-- rest destroys no membership and no access, only a correlation hint that the
-- next sync re-establishes. A duplicate is already broken state - two
-- memberships claiming one directory object - so there is no reading in which
-- both are correct.
--
-- WHICH row survives is arbitrary, and saying so matters more than it sounds.
-- MIN(uuid) picks the lexicographically smallest uuid, and uuids here come from
-- crate::util::get_uuid() = Uuid::new_v4() - random, with no time component. So
-- this is NOT "keep the oldest", which earlier wording claimed; an operator
-- reading that would believe the newer duplicate was the one cleared. There is
-- no better choice available on this table: users_organizations carries no
-- creation timestamp to order by.
-- The length clause is the postgresql-only hazard. external_id is TEXT here
-- with no cap, and the one writer that predates SCIM - upstream's Directory
-- Connector import - applies no length check at all, so a deployment using LDAP
-- DNs as externalIds can hold arbitrarily long values. A plain btree index entry
-- caps at about 2704 bytes, so a single over-long pre-existing row would make
-- the CREATE below fail outright and, because migrations run before Rocket
-- listens, leave a server that permanently refuses to start with no in-band way
-- past it. SCIM itself caps externalId at 300 characters
-- (SCIM_MAX_EXTERNAL_ID_LEN), so anything longer was never SCIM's to begin with.
UPDATE users_organizations
SET external_id = NULL
WHERE external_id IS NOT NULL
	AND (
		octet_length(external_id) > 2000
		OR uuid NOT IN (
			SELECT MIN(uuid)
			FROM users_organizations
			WHERE external_id IS NOT NULL
			GROUP BY org_uuid, external_id
		)
	);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_organizations_org_external_id_unique
	ON users_organizations (org_uuid, external_id);
