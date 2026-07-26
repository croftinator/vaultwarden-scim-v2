//
// SCIM PatchOp parsing, RFC 7644 section 3.5.2, restricted to what the User
// endpoints support. Entra quirks handled here, all observed in real syncs:
//   - "op" arrives with any casing ("Replace", "Add").
//   - boolean values may arrive as strings ("True"/"False").
//   - an operation may have no "path", carrying a value object instead
//     ({"op":"replace","value":{"active":false}}).
//
use serde::Deserialize;
use serde_json::Value;

use crate::api::scim::{error::ScimError, models::ScimBool};

pub const PATCH_OP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Deserialize)]
pub struct PatchOp {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
}

// What a User PATCH asked for, after normalization.
#[derive(Debug, Default, PartialEq)]
pub struct UserPatch {
    pub active: Option<bool>,
    pub external_id: Option<String>,
}

// Attributes Entra maps by default but Vaultwarden does not sync after
// creation. Accepted and ignored (RFC 7644 allows a service provider to
// treat immutable-for-it attributes this way in practice), because a 400
// here would surface as a sync error on every rename in the directory.
// user.name is global to the person across organizations; an org-scoped
// provisioning channel must not rewrite it.
// Accepting a write we do not apply and returning 200 means the client records
// it as done and never retries, so the directory and the vault diverge
// permanently with no signal on either side. The 200 is deliberate - a 400 on
// `userName` would quarantine the user in Entra for an attribute this server
// will never own - so the log line is the only place that divergence can
// surface. Named at warn so it is greppable when someone asks why a rename in
// the directory did not appear in the vault.
fn warn_unsynced_attribute(path: &str) {
    warn!(
        target: "scim",
        "SCIM accepted but did not apply a write to '{path}': this attribute is not synced. \
         The directory and the vault now disagree on it. See docs/scim/reference.md"
    );
}

fn is_ignored_user_attribute(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "displayname"
        || lower == "name"
        || lower.starts_with("name.")
        || lower == "emails"
        || lower.starts_with("emails[")
        || lower == "username"
        || lower == "title"
        || lower == "roles"
        || lower == "preferredlanguage"
        || lower.starts_with("addresses")
        || lower.starts_with("phonenumbers")
        || lower.starts_with("urn:ietf:params:scim:schemas:extension:enterprise:2.0:user")
}

pub fn parse_user_patch(patch: &PatchOp) -> Result<UserPatch, ScimError> {
    if !patch.schemas.iter().any(|s| s == PATCH_OP_URN) {
        return Err(ScimError::bad_request("invalidValue", "Missing PatchOp schema"));
    }
    if patch.operations.is_empty() {
        return Err(ScimError::bad_request("invalidValue", "No operations provided"));
    }

    let mut result = UserPatch::default();

    for operation in &patch.operations {
        let op = operation.op.to_lowercase();
        if op != "replace" && op != "add" && op != "remove" {
            return Err(ScimError::bad_request("invalidValue", "Unsupported patch operation"));
        }
        let is_remove = op == "remove";

        // The op is checked per-attribute, not up front: `remove` is a legal
        // RFC 7644 operation and Entra sends it whenever a mapped source
        // attribute is cleared in the directory. Rejecting it before reaching
        // the accept-and-ignore list would fail the sync on exactly the
        // attributes that list exists to tolerate.
        match operation.path.as_deref() {
            Some(op_path) if op_path.eq_ignore_ascii_case("active") => {
                if is_remove {
                    // Ambiguous, and guessing wrong either strands a member or
                    // silently drops a deprovision. Make the client be explicit.
                    return Err(ScimError::bad_request("invalidValue", "active cannot be removed, set it to false"));
                }
                let value = operation.value.clone().unwrap_or(Value::Null);
                result.active = Some(coerce_bool(value)?);
            }
            Some(op_path) if op_path.eq_ignore_ascii_case("externalid") => {
                result.external_id = Some(external_id_value(operation.value.as_ref(), is_remove)?);
            }
            Some(op_path) if is_ignored_user_attribute(op_path) => {
                warn_unsynced_attribute(op_path);
            }
            Some(_) => {
                return Err(ScimError::bad_request("invalidPath", "Unsupported patch path"));
            }
            None if is_remove => {
                // RFC 7644 section 3.5.2.2: remove requires a path.
                return Err(ScimError::bad_request("noTarget", "A remove operation must carry a path"));
            }
            None => {
                // Path-less form: the value is an object of attribute => value.
                let Some(Value::Object(map)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request(
                        "invalidValue",
                        "Operation without path must carry an object value",
                    ));
                };
                for (attribute, value) in map {
                    if attribute.eq_ignore_ascii_case("active") {
                        result.active = Some(coerce_bool(value.clone())?);
                    } else if attribute.eq_ignore_ascii_case("externalid") {
                        result.external_id = Some(external_id_value(Some(value), false)?);
                    } else if is_ignored_user_attribute(attribute) {
                        // Accepted, not synced; see is_ignored_user_attribute.
                        warn_unsynced_attribute(attribute);
                    } else {
                        return Err(ScimError::bad_request("invalidPath", "Unsupported patch attribute"));
                    }
                }
            }
        }
    }

    Ok(result)
}

// An externalId to store. A remove clears it, which reaches the database as
// NULL because Membership::set_external_id normalizes the empty string.
fn external_id_value(value: Option<&Value>, is_remove: bool) -> Result<String, ScimError> {
    if is_remove {
        return Ok(String::new());
    }
    match value {
        Some(Value::String(external_id)) => Ok(external_id.clone()),
        _ => Err(ScimError::bad_request("invalidValue", "externalId must be a string")),
    }
}

fn coerce_bool(value: Value) -> Result<bool, ScimError> {
    serde_json::from_value::<ScimBool>(value)
        .map(|b| b.0)
        .map_err(|_| ScimError::bad_request("invalidValue", "Expected a boolean value for active"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(payload: Value) -> Result<UserPatch, ScimError> {
        let parsed: PatchOp = serde_json::from_value(payload).expect("valid PatchOp json");
        parse_user_patch(&parsed)
    }

    fn ok_active(payload: Value) -> Option<bool> {
        patch(payload).expect("expected parse to succeed").active
    }

    #[test]
    fn replace_active_with_path() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        }));
        assert_eq!(active, Some(false));
    }

    #[test]
    fn entra_casing_and_string_bool() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        }));
        assert_eq!(active, Some(false));
    }

    #[test]
    fn pathless_value_object() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "value": {"active": "True"}}],
        }));
        assert_eq!(active, Some(true));
    }

    #[test]
    fn entra_mapped_attributes_are_accepted_and_ignored() {
        for path in ["displayName", "name.givenName", "emails[type eq \"work\"].value", "title", "roles"] {
            let parsed = patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [
                    {"op": "replace", "path": path, "value": "whatever"},
                    {"op": "replace", "path": "active", "value": true},
                ],
            }))
            .unwrap_or_else(|_| panic!("path {path} must be ignored, not rejected"));
            assert_eq!(parsed.active, Some(true));
        }
    }

    #[test]
    fn externalid_patch_both_forms() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "externalId", "value": "new-ext-1"}],
        }))
        .expect("valid");
        assert_eq!(parsed.external_id.as_deref(), Some("new-ext-1"));

        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "value": {"externalId": "new-ext-2", "displayName": "ignored"}}],
        }))
        .expect("valid");
        assert_eq!(parsed.external_id.as_deref(), Some("new-ext-2"));
    }

    #[test]
    fn remove_on_ignored_attributes_is_a_noop_not_an_error() {
        // Entra sends `remove` when a mapped source attribute is cleared in the
        // directory. Rejecting it would fail the sync on exactly the attributes
        // is_ignored_user_attribute exists to tolerate.
        for path in ["displayName", "name.givenName", "title", "phoneNumbers", "roles"] {
            let parsed = patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [
                    {"op": "Remove", "path": path},
                    {"op": "replace", "path": "active", "value": false},
                ],
            }))
            .unwrap_or_else(|_| panic!("remove on {path} must be ignored, not rejected"));
            assert_eq!(parsed.active, Some(false), "path {path}");
            assert_eq!(parsed.external_id, None, "path {path}");
        }
    }

    #[test]
    fn remove_externalid_clears_it() {
        // The empty string is how "clear" reaches update_external_id, which
        // stores it as NULL via Membership::set_external_id.
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "remove", "path": "externalId"}],
        }))
        .expect("remove externalId must parse");
        assert_eq!(parsed.external_id.as_deref(), Some(""));
    }

    #[test]
    fn remove_without_a_path_is_no_target() {
        // RFC 7644 section 3.5.2.2.
        let err = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "remove", "value": {"displayName": "x"}}],
        }))
        .expect_err("remove without a path must be rejected");
        assert_eq!(err.scim_type, Some("noTarget"));
    }

    #[test]
    fn rejects_bad_patches() {
        for (payload, expected_type) in [
            (
                json!({"schemas": [], "Operations": [{"op": "replace", "path": "active", "value": true}]}),
                "invalidValue",
            ),
            (json!({"schemas": [PATCH_OP_URN], "Operations": []}), "invalidValue"),
            (json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "remove", "path": "active"}]}), "invalidValue"),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "path": "wibble", "value": "x"}]}),
                "invalidPath",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "path": "active", "value": "maybe"}]}),
                "invalidValue",
            ),
            (json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "value": 3}]}), "invalidValue"),
        ] {
            match patch(payload.clone()) {
                Err(e) => assert_eq!(e.scim_type, Some(expected_type), "wrong scimType for {payload}"),
                Ok(p) => panic!("patch {payload} unexpectedly parsed to {p:?}"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Group PATCH
// ---------------------------------------------------------------------------

// One membership mutation from a PatchOp, in the order the client sent it.
// Member values are MembershipIds (the SCIM User id).
#[derive(Debug, PartialEq)]
pub enum MemberOp {
    Add(Vec<String>),
    Remove(Vec<String>),
    // Full replacement of the member set.
    Replace(Vec<String>),
}

impl MemberOp {
    pub fn values(&self) -> &[String] {
        match self {
            Self::Add(values) | Self::Remove(values) | Self::Replace(values) => values,
        }
    }
}

// What a Group PATCH asked for, after normalization.
//
// member_ops is an ordered list, not three buckets: RFC 7644 section 3.5.2
// requires operations to be applied in the order supplied. Bucketing loses
// that, so [remove X, add X] and [add X, remove X] become indistinguishable -
// and a replace in the same PatchOp as an add would silently discard the add.
#[derive(Debug, Default, PartialEq)]
pub struct GroupPatch {
    pub display_name: Option<String>,
    pub external_id: Option<String>,
    pub member_ops: Vec<MemberOp>,
}

impl GroupPatch {
    // Total member values across every operation, for the inbound size cap.
    pub fn member_count(&self) -> usize {
        self.member_ops.iter().map(|op| op.values().len()).sum()
    }
}

// Entra removes single members with a filter path instead of a value list:
//     {"op": "Remove", "path": "members[value eq \"<id>\"]"}
// (the value-array form is only sent by apps created with the
// aadOptscim062020 feature flag). Both forms must work.
fn parse_members_filter_path(path: &str) -> Option<String> {
    // SCIM attribute names are case-insensitive (RFC 7643 section 2.1) and the
    // caller's guard lowercases before testing this prefix, so stripping it
    // case-sensitively here would reject "Members[value eq ...]".
    const PREFIX: &str = "members[";
    if !path.get(..PREFIX.len()).is_some_and(|head| head.eq_ignore_ascii_case(PREFIX)) {
        return None;
    }
    let inner = path[PREFIX.len()..].strip_suffix(']')?;
    let (attribute, rest) = inner.split_once(char::is_whitespace)?;
    if !attribute.eq_ignore_ascii_case("value") {
        return None;
    }
    let (operator, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    if !operator.eq_ignore_ascii_case("eq") {
        return None;
    }
    let value = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_owned())
}

// Extracts member ids from a PATCH value: either [{"value": "id"}, ...] or a
// single {"value": "id"} object.
fn member_values(value: Option<&Value>) -> Result<Vec<String>, ScimError> {
    let invalid = || ScimError::bad_request("invalidValue", "members value must be an array of {value} objects");
    let items: Vec<&Value> = match value {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(single @ Value::Object(_)) => vec![single],
        _ => return Err(invalid()),
    };
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let Some(Value::String(id)) = item.get("value") else {
            return Err(invalid());
        };
        ids.push(id.clone());
    }
    Ok(ids)
}

pub fn parse_group_patch(patch: &PatchOp) -> Result<GroupPatch, ScimError> {
    if !patch.schemas.iter().any(|s| s == PATCH_OP_URN) {
        return Err(ScimError::bad_request("invalidValue", "Missing PatchOp schema"));
    }
    if patch.operations.is_empty() {
        return Err(ScimError::bad_request("invalidValue", "No operations provided"));
    }

    let mut result = GroupPatch::default();

    for operation in &patch.operations {
        let op = operation.op.to_lowercase();
        match operation.path.as_deref() {
            Some(op_path) if op_path.eq_ignore_ascii_case("members") => {
                result.member_ops.push(member_op(&op, member_values(operation.value.as_ref())?)?);
            }
            Some(op_path) if op_path.to_lowercase().starts_with("members[") => {
                let Some(member_id) = parse_members_filter_path(op_path) else {
                    return Err(ScimError::bad_request("invalidPath", "Unsupported members filter path"));
                };
                // Entra's single-member form. A filtered replace targets that
                // one member, so it means add, not "replace the whole set".
                let op = if op == "replace" {
                    "add"
                } else {
                    op.as_str()
                };
                result.member_ops.push(member_op(op, vec![member_id])?);
            }
            Some(op_path) if op_path.eq_ignore_ascii_case("displayname") => {
                result.display_name = Some(group_string_value(&op, operation.value.as_ref(), "displayName")?);
            }
            Some(op_path) if op_path.eq_ignore_ascii_case("externalid") => {
                result.external_id = Some(group_string_value(&op, operation.value.as_ref(), "externalId")?);
            }
            Some(_) => return Err(ScimError::bad_request("invalidPath", "Unsupported patch path for Groups")),
            None if op == "remove" => {
                // RFC 7644 section 3.5.2.2: remove requires a path.
                return Err(ScimError::bad_request("noTarget", "A remove operation must carry a path"));
            }
            None => {
                let Some(Value::Object(map)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request(
                        "invalidValue",
                        "Operation without path must carry an object value",
                    ));
                };
                for (attribute, value) in map {
                    if attribute.eq_ignore_ascii_case("displayname") {
                        result.display_name = Some(group_string_value(&op, Some(value), "displayName")?);
                    } else if attribute.eq_ignore_ascii_case("externalid") {
                        result.external_id = Some(group_string_value(&op, Some(value), "externalId")?);
                    } else if attribute.eq_ignore_ascii_case("members") {
                        result.member_ops.push(member_op(&op, member_values(Some(value))?)?);
                    } else {
                        return Err(ScimError::bad_request("invalidPath", "Unsupported patch attribute for Groups"));
                    }
                }
            }
        }
    }

    Ok(result)
}

fn member_op(op: &str, values: Vec<String>) -> Result<MemberOp, ScimError> {
    match op {
        "add" => Ok(MemberOp::Add(values)),
        "remove" => Ok(MemberOp::Remove(values)),
        "replace" => Ok(MemberOp::Replace(values)),
        _ => Err(ScimError::bad_request("invalidValue", "Unsupported operation on members")),
    }
}

// A displayName/externalId value. The op is honoured rather than ignored: a
// remove clears the attribute (empty string, which Group::set_external_id
// stores as NULL) instead of setting it to whatever value tagged along.
fn group_string_value(op: &str, value: Option<&Value>, attribute: &str) -> Result<String, ScimError> {
    match op {
        "remove" => Ok(String::new()),
        "add" | "replace" => match value {
            Some(Value::String(text)) => Ok(text.clone()),
            _ => Err(ScimError::bad_request("invalidValue", &format!("{attribute} must be a string"))),
        },
        _ => Err(ScimError::bad_request("invalidValue", &format!("Unsupported operation on {attribute}"))),
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn patch(payload: Value) -> Result<GroupPatch, ScimError> {
        let parsed: PatchOp = serde_json::from_value(payload).expect("valid PatchOp json");
        parse_group_patch(&parsed)
    }

    #[test]
    fn add_and_remove_member_value_lists() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "Add", "path": "members", "value": [{"value": "member-1"}, {"value": "member-2"}]},
                {"op": "remove", "path": "members", "value": [{"value": "member-3"}]},
            ],
        }))
        .expect("valid");
        assert_eq!(
            parsed.member_ops,
            vec![
                MemberOp::Add(vec!["member-1".to_owned(), "member-2".to_owned()]),
                MemberOp::Remove(vec!["member-3".to_owned()]),
            ]
        );
    }

    #[test]
    fn member_ops_keep_the_order_they_arrived_in() {
        // RFC 7644 section 3.5.2: operations apply in the order supplied.
        // Bucketing by op would make these two PatchOps indistinguishable,
        // and both would resolve to "removed".
        let remove_then_add = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "remove", "path": "members", "value": [{"value": "m-1"}]},
                {"op": "add", "path": "members", "value": [{"value": "m-1"}]},
            ],
        }))
        .expect("valid");
        assert_eq!(
            remove_then_add.member_ops,
            vec![MemberOp::Remove(vec!["m-1".to_owned()]), MemberOp::Add(vec!["m-1".to_owned()])]
        );

        let add_then_remove = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "add", "path": "members", "value": [{"value": "m-1"}]},
                {"op": "remove", "path": "members", "value": [{"value": "m-1"}]},
            ],
        }))
        .expect("valid");
        assert_ne!(add_then_remove.member_ops, remove_then_add.member_ops, "order must be preserved, not bucketed");
    }

    #[test]
    fn a_replace_does_not_swallow_other_member_ops() {
        // The bucketed form applied the replace and silently discarded the add,
        // returning 200 while the member never joined.
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "replace", "path": "members", "value": [{"value": "m-1"}]},
                {"op": "add", "path": "members", "value": [{"value": "m-2"}]},
            ],
        }))
        .expect("valid");
        assert_eq!(
            parsed.member_ops,
            vec![MemberOp::Replace(vec!["m-1".to_owned()]), MemberOp::Add(vec!["m-2".to_owned()])]
        );
    }

    #[test]
    fn group_remove_clears_display_name_and_external_id() {
        // Previously the op was computed and then ignored on these branches, so
        // a remove carrying a value SET the attribute instead of clearing it.
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "remove", "path": "externalId", "value": "stale-value"},
            ],
        }))
        .expect("valid");
        assert_eq!(parsed.external_id.as_deref(), Some(""), "remove must clear, not set");
    }

    #[test]
    fn entra_filter_path_removal() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "Remove", "path": "members[value eq \"member-9\"]"}],
        }))
        .expect("valid");
        assert_eq!(parsed.member_ops, vec![MemberOp::Remove(vec!["member-9".to_owned()])]);
    }

    #[test]
    fn filter_path_attribute_name_is_case_insensitive() {
        // RFC 7643 section 2.1: attribute names are case-insensitive. The
        // dispatch guard lowercases the path, so the parser must too or the
        // request is accepted into the branch and then rejected as invalidPath.
        for path in ["Members[value eq \"m-1\"]", "MEMBERS[Value EQ \"m-1\"]"] {
            let parsed = patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [{"op": "Remove", "path": path}],
            }))
            .unwrap_or_else(|_| panic!("path {path} must parse"));
            assert_eq!(parsed.member_ops, vec![MemberOp::Remove(vec!["m-1".to_owned()])], "path {path}");
        }
    }

    #[test]
    fn replace_members_and_rename() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "replace", "path": "members", "value": [{"value": "only-member"}]},
                {"op": "replace", "path": "displayName", "value": "New Group Name"},
            ],
        }))
        .expect("valid");
        assert_eq!(parsed.member_ops, vec![MemberOp::Replace(vec!["only-member".to_owned()])]);
        assert_eq!(parsed.display_name.as_deref(), Some("New Group Name"));
    }

    #[test]
    fn group_patch_rejects_garbage() {
        for (payload, expected_type) in [
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "remove", "path": "members[display eq \"x\"]"}]}),
                "invalidPath",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "add", "path": "members", "value": ["bare-string"]}]}),
                "invalidValue",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "add", "path": "wibble", "value": 1}]}),
                "invalidPath",
            ),
        ] {
            match patch(payload.clone()) {
                Err(e) => assert_eq!(e.scim_type, Some(expected_type), "wrong scimType for {payload}"),
                Ok(p) => panic!("group patch {payload} unexpectedly parsed to {p:?}"),
            }
        }
    }
}

#[cfg(test)]
mod review_regression_tests {
    use super::*;
    use serde_json::json;

    fn user_patch(payload: Value) -> Result<UserPatch, ScimError> {
        parse_user_patch(&serde_json::from_value(payload).expect("valid PatchOp"))
    }

    fn group_patch(payload: Value) -> Result<GroupPatch, ScimError> {
        parse_group_patch(&serde_json::from_value(payload).expect("valid PatchOp"))
    }

    // Entra's single-member filter form with `replace` targets THAT member, so
    // it means add. If this ever regresses to MemberOp::Replace it would wipe
    // every other member of the group while returning 200.
    #[test]
    fn a_filtered_replace_adds_one_member_rather_than_replacing_the_set() {
        for op in ["replace", "Replace", "REPLACE"] {
            let parsed = group_patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [{"op": op, "path": "members[value eq \"m-1\"]"}],
            }))
            .unwrap_or_else(|_| panic!("op {op} must parse"));
            assert_eq!(
                parsed.member_ops,
                vec![MemberOp::Add(vec!["m-1".to_owned()])],
                "a filtered {op} targets one member, so it must not replace the whole set"
            );
        }
    }

    // The enterprise extension is the branch Entra exercises most: department,
    // manager and employeeNumber are default mappings in its provisioning
    // template. Rejecting them would fail the sync on every user.
    #[test]
    fn enterprise_extension_attributes_are_accepted_and_ignored() {
        const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        for attribute in ["department", "manager", "employeeNumber", "costCenter", "organization"] {
            let path = format!("{ENTERPRISE}:{attribute}");
            let parsed = user_patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [
                    {"op": "replace", "path": path, "value": "anything"},
                    {"op": "replace", "path": "active", "value": false},
                ],
            }))
            .unwrap_or_else(|_| panic!("{path} must be ignored, not rejected"));
            assert_eq!(parsed.active, Some(false), "path {path}");
            assert_eq!(parsed.external_id, None, "path {path}");
        }
    }

    // The path-less form is a separate branch from the path form, and nothing
    // covered an ignored attribute arriving through it.
    #[test]
    fn ignored_attributes_are_also_tolerated_in_the_path_less_form() {
        let parsed = user_patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "value": {
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "Engineering",
                "displayName": "Ignored Name",
                "preferredLanguage": "en-AU",
                "active": false,
            }}],
        }))
        .expect("a path-less patch of ignored attributes plus active must parse");
        assert_eq!(parsed.active, Some(false));
        assert_eq!(parsed.external_id, None);
    }
}
