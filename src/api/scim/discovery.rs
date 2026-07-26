//
// SCIM discovery endpoints, RFC 7643 section 5 and RFC 7644 section 4.
//
// Static metadata, served behind the ScimToken guard like everything else
// under /scim. Entra ID does not require these for Test Connection (that only
// needs a 200 ListResponse on a userName filter), but other SCIM clients read
// them, and they are cheap.
//
use rocket::Route;
use serde_json::Value;

use crate::{
    CONFIG,
    api::scim::{ScimResponse, error::ScimError, guard::ScimToken},
    db::models::OrganizationId,
};

pub fn routes() -> Vec<Route> {
    routes![service_provider_config, resource_types, resource_type, schemas, schema]
}

pub(crate) const LIST_RESPONSE_URN: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const USER_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub(crate) const SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Schema";

fn scim_base(org_id: &OrganizationId) -> String {
    format!("{}/scim/v2/{org_id}", CONFIG.domain())
}

fn list_response(resources: &[Value]) -> Value {
    json!({
        "schemas": [LIST_RESPONSE_URN],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources,
    })
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/ServiceProviderConfig")]
fn service_provider_config(token: ScimToken) -> ScimResponse {
    ScimResponse::ok(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/croftinator/vaultwarden-scim-v2",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": crate::api::scim::SCIM_MAX_RESULTS },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Static bearer token generated per organization",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{}/ServiceProviderConfig", scim_base(&token.org_uuid)),
        },
    }))
}

fn user_resource_type(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "User",
        "name": "User",
        "endpoint": "/Users",
        "description": "Organization member",
        "schema": USER_SCHEMA_URN,
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") },
    })
}

fn group_resource_type(base: &str) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
        "id": "Group",
        "name": "Group",
        "endpoint": "/Groups",
        "description": "Organization group",
        "schema": GROUP_SCHEMA_URN,
        "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
    })
}

fn user_schema(base: &str) -> Value {
    json!({
        "schemas": [SCHEMA_URN],
        "id": USER_SCHEMA_URN,
        "name": "User",
        "description": "Organization member. Only the attributes listed here are honoured; anything else is accepted and ignored, per RFC 7643 section 2.1.",
        "attributes": user_attributes(),
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{USER_SCHEMA_URN}") },
    })
}

fn group_schema(base: &str) -> Value {
    json!({
        "schemas": [SCHEMA_URN],
        "id": GROUP_SCHEMA_URN,
        "name": "Group",
        "description": "Organization group. SCIM owns group existence and membership; collection access stays an in-app admin decision.",
        "attributes": group_attributes(),
        "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA_URN}") },
    })
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/ResourceTypes")]
fn resource_types(token: ScimToken) -> ScimResponse {
    let base = scim_base(&token.org_uuid);
    let mut resources = vec![user_resource_type(&base)];
    // Advertise Group only when the server can serve it: every /Groups handler
    // answers 501 without ORG_GROUPS_ENABLED, and a client that reads discovery
    // to decide what to sync must not be told about an endpoint that refuses.
    if crate::api::scim::org_groups_enabled() {
        resources.push(group_resource_type(&base));
    }
    ScimResponse::ok(list_response(&resources))
}

// RFC 7644 section 4 defines /ResourceTypes/{id} as retrievable, and every
// entry above advertises its own meta.location. Without this handler each of
// those locations 404s, so a conformance-checking client that dereferences
// what discovery told it about gets a dead link.
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/ResourceTypes/<resource_id>")]
fn resource_type(resource_id: &str, token: ScimToken) -> Result<ScimResponse, ScimError> {
    let base = scim_base(&token.org_uuid);
    let groups_on = crate::api::scim::org_groups_enabled();
    match resource_id {
        "User" => Ok(ScimResponse::ok(user_resource_type(&base))),
        "Group" if groups_on => Ok(ScimResponse::ok(group_resource_type(&base))),
        _ => Err(ScimError::not_found()),
    }
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/Schemas")]
fn schemas(token: ScimToken) -> ScimResponse {
    let base = scim_base(&token.org_uuid);
    let mut resources = vec![user_schema(&base)];
    // Kept in step with ResourceTypes: no Group schema when Groups are disabled.
    if crate::api::scim::org_groups_enabled() {
        resources.push(group_schema(&base));
    }
    ScimResponse::ok(list_response(&resources))
}

// As with /ResourceTypes/{id}: RFC 7644 section 4 makes /Schemas/{id}
// retrievable, and the collection advertises these exact URNs as locations.
#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/Schemas/<schema_id>")]
fn schema(schema_id: &str, token: ScimToken) -> Result<ScimResponse, ScimError> {
    let base = scim_base(&token.org_uuid);
    let groups_on = crate::api::scim::org_groups_enabled();
    if schema_id == USER_SCHEMA_URN {
        return Ok(ScimResponse::ok(user_schema(&base)));
    }
    if schema_id == GROUP_SCHEMA_URN && groups_on {
        return Ok(ScimResponse::ok(group_schema(&base)));
    }
    Err(ScimError::not_found())
}

// One entry of a Schema resource's `attributes` array, RFC 7643 section 7.
// Every field is required there, so none of them are optional here.
fn attribute(
    name: &str,
    attr_type: &str,
    multi_valued: bool,
    required: bool,
    mutability: &str,
    uniqueness: &str,
) -> Value {
    json!({
        "name": name,
        "type": attr_type,
        "multiValued": multi_valued,
        "description": "",
        "required": required,
        "caseExact": false,
        "mutability": mutability,
        "returned": "default",
        "uniqueness": uniqueness,
    })
}

// Exactly what the Users handlers honour.
//
// These are `immutable`, not `readOnly`. RFC 7643 section 7 defines readOnly as
// "the attribute SHALL NOT be modified" by a client at all, so a schema-driven
// client (Okta, OneLogin, Entra's schema-discovery step, Microsoft's SCIM
// Validator) will refuse to map a readOnly attribute and will not send it. That
// is unsupportable here: post_user REQUIRES userName, and it reads displayName,
// name.* and emails[] on create - declaring them readOnly would tell a client
// the one attribute it must send is one it is forbidden to send, and a tenant
// mapping the routable address only into emails[] would create with no usable
// address and 400 on every cycle.
//
// `immutable` says exactly what the implementation does: accepted at create,
// not rewritten afterwards. userName is the login identity, and name/displayName
// live on the global User row shared across organizations, so an org-scoped
// channel must not own them after the fact.
//
// externalId is deliberately absent: RFC 7643 section 3.1 makes it a COMMON
// attribute alongside id and meta, present on every resource and not part of any
// schema's attribute definition. Listing it makes the served schema diverge from
// the section 8.7.1 baseline a validator compares against.
fn user_attributes() -> Vec<Value> {
    let mut name = attribute("name", "complex", false, false, "immutable", "none");
    name["subAttributes"] = json!([
        attribute("formatted", "string", false, false, "immutable", "none"),
        attribute("givenName", "string", false, false, "immutable", "none"),
        attribute("familyName", "string", false, false, "immutable", "none"),
    ]);

    let mut emails = attribute("emails", "complex", true, false, "immutable", "none");
    emails["subAttributes"] = json!([
        attribute("value", "string", false, true, "immutable", "none"),
        attribute("type", "string", false, false, "immutable", "none"),
        attribute("primary", "boolean", false, false, "immutable", "none"),
    ]);

    vec![
        attribute("userName", "string", false, true, "immutable", "server"),
        attribute("displayName", "string", false, false, "immutable", "none"),
        name,
        emails,
        attribute("active", "boolean", false, false, "readWrite", "none"),
    ]
}

// externalId omitted for the same reason as on User: it is a common attribute,
// not a schema-defined one.
fn group_attributes() -> Vec<Value> {
    let mut members = attribute("members", "complex", true, false, "readWrite", "none");
    members["subAttributes"] = json!([attribute("value", "string", false, true, "immutable", "none")]);

    vec![attribute("displayName", "string", false, true, "readWrite", "none"), members]
}
