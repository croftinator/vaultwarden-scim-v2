-- See the sibling migration for users_organizations. `groups` is a reserved
-- word in mysql 8 and must be backticked.
DROP INDEX idx_groups_org_external_id ON `groups`;
