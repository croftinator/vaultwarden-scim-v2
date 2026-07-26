use chrono::{NaiveDateTime, Utc};
use derive_more::Display;
use diesel::prelude::*;

use crate::{
    api::EmptyResult,
    crypto,
    db::{DbConn, models::OrganizationId, schema::scim_api_key},
    error::MapResult,
};

#[derive(Identifiable, Queryable, Insertable, AsChangeset)]
#[diesel(table_name = scim_api_key)]
#[diesel(primary_key(uuid))]
pub struct ScimApiKey {
    pub uuid: ScimApiKeyId,
    pub org_uuid: OrganizationId,
    // sha256 hex digest of the token secret. The plaintext secret is shown once
    // at generation time and never stored or logged.
    pub key_hash: String,
    // Reversible kill switch, set by `set_enabled` behind the Owner-gated
    // management endpoint. The guard only accepts an enabled key via
    // find_active_by_org (asserted in the uniform-401 authz matrix test), so
    // disabling stops provisioning immediately without destroying the digest.
    pub enabled: bool,
    pub created_at: NaiveDateTime,
    pub revision_date: NaiveDateTime,
    // Last time this key successfully authenticated a SCIM request. NULL means
    // it has not been used since the column existed, which is deliberately
    // distinguishable from "used a long time ago". Coarse by design - see
    // `touch_last_used`.
    pub last_used_at: Option<NaiveDateTime>,
}

// How stale `last_used_at` is allowed to get before a successful request writes
// it again. A full Entra sync is thousands of authenticated requests, and this
// column exists for an operator reading a status page, not for forensics - so
// recording it once an hour turns an unbounded write amplification on the hot
// auth path into at most one UPDATE per organization per hour.
const LAST_USED_RESOLUTION_SECONDS: i64 = 3600;

#[derive(Clone, Debug, DieselNewType, Display, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimApiKeyId(String);

impl ScimApiKey {
    pub fn new(org_uuid: OrganizationId, key_hash: String) -> Self {
        let now = Utc::now().naive_utc();
        Self {
            uuid: ScimApiKeyId(crate::util::get_uuid()),
            org_uuid,
            key_hash,
            enabled: true,
            created_at: now,
            revision_date: now,
            last_used_at: None,
        }
    }

    /// Records that this key just authenticated a request, at most once per
    /// `LAST_USED_RESOLUTION_SECONDS`.
    ///
    /// Returns without touching the database when the stored value is already
    /// recent enough, so the common case on a sync burst costs nothing. Failures
    /// are swallowed: this is operator telemetry, and losing it must never turn
    /// a valid SCIM request into an error.
    pub async fn touch_last_used(&self, conn: &DbConn) {
        let now = Utc::now().naive_utc();
        if let Some(last) = self.last_used_at
            && (now - last).num_seconds() < LAST_USED_RESOLUTION_SECONDS
        {
            return;
        }
        let org_uuid = self.org_uuid.clone();
        // Filtered on this key's OWN uuid as well as the org. An Owner can
        // rotate or disable the credential while a request is in flight, and
        // rotation writes a fresh uuid into the org's row; an org-only filter
        // would then stamp this request's timestamp onto the NEW key. The
        // status endpoint exists precisely so an operator can tell a live key
        // from a dead one, and a freshly minted key reporting usage it never
        // had is the one reading that must not happen.
        let key_uuid = self.uuid.clone();
        let written = conn
            .run(move |conn| {
                diesel::update(
                    scim_api_key::table
                        .filter(scim_api_key::org_uuid.eq(&org_uuid))
                        .filter(scim_api_key::uuid.eq(&key_uuid)),
                )
                .set(scim_api_key::last_used_at.eq(Some(now)))
                .execute(conn)
            })
            .await;
        if let Err(e) = written {
            debug!(target: "scim", "Could not record SCIM key last-used time: {e:?}");
        }
    }

    /// Enables or disables the key without deleting it. The guard only accepts
    /// an enabled key (`find_active_by_org`), so this is a reversible kill
    /// switch: it stops provisioning immediately while keeping the digest, so
    /// re-enabling does not require re-pasting a new token into the IdP.
    pub async fn set_enabled(org_uuid: &OrganizationId, enabled: bool, conn: &DbConn) -> EmptyResult {
        let org_uuid = org_uuid.clone();
        let now = Utc::now().naive_utc();
        conn.run(move |conn| {
            diesel::update(scim_api_key::table.filter(scim_api_key::org_uuid.eq(&org_uuid)))
                .set((scim_api_key::enabled.eq(enabled), scim_api_key::revision_date.eq(now)))
                .execute(conn)
                .map_res("Error updating SCIM api key state")
        })
        .await
    }

    // Constant-time comparison against a plaintext secret's digest. A dummy
    // digest is compared when no key row exists so the caller can keep the
    // verification cost independent of row presence.
    pub fn check_valid_secret(&self, secret: &str) -> bool {
        crypto::ct_eq(&self.key_hash, crypto::sha256_hex(secret.as_bytes()))
    }

    pub async fn save(&self, conn: &DbConn) -> EmptyResult {
        // Standard Vaultwarden upsert idiom: replace_into with an update
        // fallback on sqlite/mysql, ON CONFLICT upsert on postgresql. This is
        // also the rotation path - mint_scim_token overwrites the org's row
        // here rather than deleting and re-inserting it.
        db_run! { conn:
            sqlite, mysql {
                match diesel::replace_into(scim_api_key::table)
                    .values(self)
                    .execute(conn)
                {
                    Ok(_) => Ok(()),
                    // Record already exists and causes a Foreign Key Violation because replace_into() wants to delete the record first.
                    Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::ForeignKeyViolation, _)) => {
                        // Target the row by org_uuid, NOT by uuid. Unlike the
                        // upstream models this idiom is copied from, every mint
                        // builds a ScimApiKey with a FRESH uuid, so a
                        // uuid-filtered update matches no row on rotation: it
                        // would affect nothing, report success, and leave the
                        // previous key row intact. The admin would be handed a
                        // token that was never stored while the token they meant
                        // to revoke kept working - a rotation that silently does
                        // not revoke. org_uuid is UNIQUE and is the column the
                        // conflict is actually on.
                        match diesel::update(scim_api_key::table)
                            .filter(scim_api_key::org_uuid.eq(&self.org_uuid))
                            // Explicit for the same reason as the postgresql arm:
                            // AsChangeset would silently skip the primary key.
                            .set((
                                scim_api_key::uuid.eq(&self.uuid),
                                scim_api_key::key_hash.eq(&self.key_hash),
                                scim_api_key::enabled.eq(self.enabled),
                                scim_api_key::created_at.eq(self.created_at),
                                scim_api_key::revision_date.eq(self.revision_date),
                                // Reset on rotation: a freshly minted credential
                                // has never been used, and carrying the previous
                                // key's timestamp would make a dead token look live.
                                scim_api_key::last_used_at.eq(self.last_used_at),
                            ))
                            .execute(conn)
                        {
                            // Nothing was written, so no stored digest can ever
                            // match the token the caller is about to hand out.
                            // Fail loudly instead of returning a dead credential.
                            Ok(0) => Err(diesel::result::Error::NotFound),
                            Ok(_) => Ok(()),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }.map_res("Error saving SCIM api key")
            }
            postgresql {
                // Conflict on org_uuid, not on the primary key: the table holds
                // at most one key per organization (org_uuid is UNIQUE), and a
                // fresh row carries a fresh uuid, so a PK-targeted upsert would
                // raise a unique violation exactly where replace_into succeeds
                // on the other two backends.
                diesel::insert_into(scim_api_key::table)
                    .values(self)
                    .on_conflict(scim_api_key::org_uuid)
                    .do_update()
                    // Columns listed explicitly instead of `.set(self)`, because
                    // AsChangeset never writes the primary key. With `.set(self)`
                    // PostgreSQL would keep the ORIGINAL uuid across a rotation
                    // while sqlite/mysql replace_into writes the fresh one, so the
                    // stored row would quietly differ by backend.
                    .set((
                        scim_api_key::uuid.eq(&self.uuid),
                        scim_api_key::key_hash.eq(&self.key_hash),
                        scim_api_key::enabled.eq(self.enabled),
                        scim_api_key::created_at.eq(self.created_at),
                        scim_api_key::revision_date.eq(self.revision_date),
                        // Reset on rotation; see the sqlite/mysql arm.
                        scim_api_key::last_used_at.eq(self.last_used_at),
                    ))
                    .execute(conn)
                    .map_res("Error saving SCIM api key")
            }
        }
    }

    pub async fn find_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| scim_api_key::table.filter(scim_api_key::org_uuid.eq(org_uuid)).first::<Self>(conn).ok())
            .await
    }

    pub async fn find_active_by_org(org_uuid: &OrganizationId, conn: &DbConn) -> Option<Self> {
        conn.run(move |conn| {
            scim_api_key::table
                .filter(scim_api_key::org_uuid.eq(org_uuid))
                .filter(scim_api_key::enabled.eq(true))
                .first::<Self>(conn)
                .ok()
        })
        .await
    }

    pub async fn delete_all_by_organization(org_uuid: &OrganizationId, conn: &DbConn) -> EmptyResult {
        conn.run(move |conn| {
            diesel::delete(scim_api_key::table.filter(scim_api_key::org_uuid.eq(org_uuid)))
                .execute(conn)
                .map_res("Error removing SCIM api key from organization")
        })
        .await
    }
}
