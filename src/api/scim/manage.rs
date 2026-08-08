//
// Management endpoints for the per-organization SCIM api key. These live
// under /api (not /scim) and require an interactive session plus password or
// OTP re-authentication, mirroring the existing organization api-key rotation
// endpoints.
//
// The plaintext token is returned exactly once, from the generate/rotate
// call. Only its sha256 digest is stored.
//
// Minting and revoking the key require OwnerHeaders, not AdminHeaders, even
// though the neighbouring organization api-key endpoints settle for admin.
// The reason is the blast radius of what gets minted: a SCIM token can revoke
// an Owner (revoke_member only refuses the LAST confirmed one), while the web
// vault forbids exactly that - `organizations.rs` rejects an Admin revoking an
// Owner with "Only owners can revoke other owners". Since AdminHeaders resolves
// for Admin and Owner alike (`is_confirmed_and_admin` tests
// `membership_type >= Admin`), gating the mint on admin would let an Admin issue
// itself a credential that does what its own session is denied, and
// `reject_privileged_grant` then blocks SCIM from putting the Owner back.
// The credential may only be created by the role authorised to use it.
//
// `scim_status` is Owner-gated for the same reason, though it only reads. It
// was the one endpoint here left on AdminHeaders, which was an inconsistency
// rather than a decision: it reports the credential's configured/enabled state
// and its lastUsedAt, and it reports how many of the organization's Owners are
// directory-linked - the break-glass posture. That last field is a map of where
// to attack the organization's recovery path, and an Admin is exactly the role
// that cannot mint, revoke or disable the credential it describes.
//
// Read access was tightened rather than made to require a password/OTP step-up
// like its mutating siblings. A step-up needs a request body, so it would have
// forced this GET to become a POST - a breaking change to the endpoint's shape,
// for a read. Matching the role gate closes the same privilege gap without
// changing the contract.
//
use rocket::{Route, serde::json::Json};

use crate::{
    CONFIG,
    api::{EmptyResult, JsonResult, PasswordOrOtpData, core::log_event},
    auth::OwnerHeaders,
    crypto,
    db::{
        DbConn,
        models::{EventType, Membership, MembershipType, OrganizationId, ScimApiKey},
    },
    util::format_date,
};

pub fn routes() -> Vec<Route> {
    routes![generate_scim_key, delete_scim_key, set_scim_key_enabled, scim_status]
}

// Applied to MINTING only, deliberately. Deleting the key, flipping the kill
// switch, and reading the status are all teardown or inspection: an operator who
// has just turned SCIM off still needs to revoke the credential that was live a
// moment ago, and refusing that would strand it. Only handing out a NEW
// credential for a disabled feature is nonsense.
fn check_scim_enabled() -> EmptyResult {
    if !CONFIG.scim_enabled() {
        err!("SCIM support is disabled")
    }
    Ok(())
}

// Records a SCIM token management action in the org event log under the acting
// admin's own identity (this is an interactive, re-authenticated admin action,
// not a SCIM-driven one, so it does not use the synthetic SCIM actor). The org
// itself is the event source; OrganizationUpdated is the closest existing type,
// matching how the admin panel logs org-level configuration changes.
async fn log_scim_key_event(headers: &OwnerHeaders, org_id: &OrganizationId, conn: &DbConn) {
    log_event(
        EventType::OrganizationUpdated as i32,
        org_id,
        org_id,
        &headers.user.uuid,
        headers.device.atype,
        &headers.ip.ip,
        conn,
    )
    .await;
}

// The single place a SCIM token is minted. Generates the secret, replaces any
// existing key row (rotation: the previous token stops working immediately),
// and returns the full bearer token plus the stored row. The integration
// tests call this too, so the minted format and the guard's verification
// cannot drift apart.
pub(crate) async fn mint_scim_token(
    org_id: &OrganizationId,
    conn: &DbConn,
) -> Result<(String, ScimApiKey), crate::Error> {
    // 256-bit secret; the stored digest can only be brute-forced, not inverted.
    let secret = crypto::encode_random_bytes::<32>(&data_encoding::BASE64URL_NOPAD);
    let key_hash = crypto::sha256_hex(secret.as_bytes());

    // Rotation replaces the row in a single upsert rather than deleting and
    // then inserting. A delete-then-insert that fails on the insert would leave
    // the organization with no key at all - the old token already dead, the new
    // one never issued - and every SCIM request 401ing until an admin notices.
    // org_uuid is UNIQUE, so this overwrites whatever key the org had.
    let scim_key = ScimApiKey::new(org_id.clone(), key_hash);
    scim_key.save(conn).await?;

    Ok((format!("scim_v1.{org_id}.{secret}"), scim_key))
}

#[post("/organizations/<org_id>/scim/api-key", data = "<data>")]
async fn generate_scim_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    check_scim_enabled()?;
    data.into_inner().validate(&headers.user, true, &conn).await?;

    let (token, scim_key) = mint_scim_token(&org_id, &conn).await?;
    log_scim_key_event(&headers, &org_id, &conn).await;

    Ok(Json(json!({
        "object": "scim-api-key",
        "token": token,
        "scimBaseUrl": format!("{}/scim/v2/{org_id}", CONFIG.domain()),
        "revisionDate": format_date(&scim_key.revision_date),
    })))
}

#[delete("/organizations/<org_id>/scim/api-key", data = "<data>")]
async fn delete_scim_key(
    org_id: OrganizationId,
    data: Json<PasswordOrOtpData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    data.into_inner().validate(&headers.user, true, &conn).await?;

    ScimApiKey::delete_all_by_organization(&org_id, &conn).await?;
    log_scim_key_event(&headers, &org_id, &conn).await;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SetEnabledData {
    enabled: bool,
    #[serde(flatten)]
    auth: PasswordOrOtpData,
}

// Reversible kill switch for the organization's SCIM credential.
//
// Deleting the key also stops provisioning, but it destroys the digest, so
// resuming means minting a new token and re-pasting it into the IdP. Disabling
// keeps the digest, so an operator who suspects a runaway sync - or who wants
// provisioning paused during a maintenance window - can stop it now and resume
// without touching Entra at all. The guard already refuses a disabled key via
// find_active_by_org; before this endpoint nothing could ever set the flag.
#[put("/organizations/<org_id>/scim/api-key/enabled", data = "<data>")]
async fn set_scim_key_enabled(
    org_id: OrganizationId,
    data: Json<SetEnabledData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }
    let data = data.into_inner();
    data.auth.validate(&headers.user, true, &conn).await?;

    if ScimApiKey::find_by_org(&org_id, &conn).await.is_none() {
        err!("No SCIM api key is configured for this organization");
    }
    ScimApiKey::set_enabled(&org_id, data.enabled, &conn).await?;
    log_scim_key_event(&headers, &org_id, &conn).await;

    Ok(Json(json!({
        "object": "scim-api-key",
        "keyEnabled": data.enabled,
    })))
}

// Confirmed Owners that SCIM has linked to a directory object.
//
// The erosion this detects is real and otherwise silent: SCIM provisions
// somebody as a plain member and sets their externalId, an admin later promotes
// them to Owner in the web vault, and that Owner is now a directory identity.
// Repeat for everyone and no Owner is left that survives a compromise of the
// identity provider. SCIM can no longer link a privileged membership itself, so
// this can only grow through a human promotion, never through a sync.
//
// Deliberately reported as "linked", not as "break-glass accounts": the absence
// of an externalId does NOT prove an account is absent from the directory. An
// admin kept out of scope by an Entra scoping filter is never provisioned and so
// never carries one either. Whether a genuine break-glass Owner exists is a fact
// about the directory that this server cannot see; all it can prove is the
// negative - that every Owner is directory-linked, which is unambiguously bad.
// Two aggregate queries, not a full scan: the endpoint needs only the counts,
// so loading and deserializing every membership row of the organization to
// filter them in Rust bought nothing.
async fn count_directory_linked_owners(org_id: &OrganizationId, conn: &DbConn) -> (i64, i64) {
    let confirmed = Membership::count_confirmed_by_org_and_type(org_id, MembershipType::Owner, conn).await;
    let linked =
        Membership::count_confirmed_directory_linked_by_org_and_type(org_id, MembershipType::Owner, conn).await;
    (linked, confirmed)
}

#[get("/organizations/<org_id>/scim/status")]
async fn scim_status(org_id: OrganizationId, headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    if org_id != headers.org_id {
        err!("Organization not found", "Organization id's do not match");
    }

    let scim_key = ScimApiKey::find_by_org(&org_id, &conn).await;
    let (linked_owners, confirmed_owners) = count_directory_linked_owners(&org_id, &conn).await;
    Ok(Json(json!({
        "object": "scim-status",
        "scimEnabled": CONFIG.scim_enabled(),
        "keyConfigured": scim_key.is_some(),
        "keyEnabled": scim_key.as_ref().is_some_and(|k| k.enabled),
        "createdAt": scim_key.as_ref().map(|k| format_date(&k.created_at)),
        "revisionDate": scim_key.as_ref().map(|k| format_date(&k.revision_date)),
        // null means the key has not authenticated a request since this column
        // existed, which is the signal an operator wants: a configured key that
        // never reports usage is either not wired into the IdP or is dead.
        // Recorded at hour resolution, so it lags a live sync by up to an hour.
        "lastUsedAt": scim_key.as_ref().and_then(|k| k.last_used_at.as_ref().map(format_date)),
        "confirmedOwners": confirmed_owners,
        "directoryLinkedOwners": linked_owners,
        "breakGlassWarning": (confirmed_owners > 0 && linked_owners == confirmed_owners).then_some(
            "Every confirmed Owner of this organization carries a SCIM externalId, so every one of \
             them was provisioned from the identity provider. Keep at least one Owner that exists \
             only in Vaultwarden, or a compromise of the IdP leaves this organization with no \
             recovery path. Note that a low directoryLinkedOwners count does not by itself prove a \
             break-glass account exists: an admin excluded by an IdP scoping filter is never \
             provisioned and carries no externalId either."
        ),
    })))
}
