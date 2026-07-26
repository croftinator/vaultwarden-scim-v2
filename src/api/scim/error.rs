//
// SCIM error envelope, RFC 7644 section 3.12.
//
// Every error leaving the /scim mount must use this shape. Auth failures are
// deliberately uniform: the guard logs the specific cause server-side and the
// caller always receives the same 401 body, so responses carry no signal about
// which check failed.
//
use std::io::Cursor;

use rocket::{
    http::{ContentType, Status},
    request::Request,
    response::{self, Responder, Response},
};

pub const SCIM_ERROR_URN: &str = "urn:ietf:params:scim:api:messages:2.0:Error";

#[derive(Debug)]
pub struct ScimError {
    pub status: Status,
    pub scim_type: Option<&'static str>,
    pub detail: String,
    // Seconds for a Retry-After header. Only set on 429, so a throttled client
    // has something better than a guess to back off by.
    pub retry_after: Option<u64>,
}

impl ScimError {
    fn new(status: Status, scim_type: Option<&'static str>, detail: &str) -> Self {
        Self {
            status,
            scim_type,
            detail: String::from(detail),
            retry_after: None,
        }
    }

    pub fn unauthorized() -> Self {
        Self::new(Status::Unauthorized, None, "Unauthorized")
    }

    pub fn too_many_requests() -> Self {
        Self {
            retry_after: Some(crate::CONFIG.scim_ratelimit_seconds().max(1)),
            ..Self::new(Status::TooManyRequests, None, "Too many requests")
        }
    }

    pub fn conflict(scim_type: &'static str, detail: &str) -> Self {
        Self::new(Status::Conflict, Some(scim_type), detail)
    }

    pub fn payload_too_large() -> Self {
        Self::new(Status::PayloadTooLarge, None, "Payload too large")
    }

    pub fn not_found() -> Self {
        Self::new(Status::NotFound, None, "Resource not found")
    }

    pub fn bad_request(scim_type: &'static str, detail: &str) -> Self {
        Self::new(Status::BadRequest, Some(scim_type), detail)
    }

    pub fn not_implemented(detail: &str) -> Self {
        Self::new(Status::NotImplemented, None, detail)
    }

    pub fn internal() -> Self {
        Self::new(Status::InternalServerError, None, "Internal server error")
    }

    // Envelope for a status with no dedicated constructor, used by the default
    // catcher. The detail is Rocket's own reason phrase, never request content.
    pub fn from_status(status: Status) -> Self {
        if status == Status::TooManyRequests {
            return Self::too_many_requests();
        }
        Self::new(status, None, status.reason().unwrap_or("Request failed"))
    }

    fn body(&self) -> String {
        let mut body = json!({
            "schemas": [SCIM_ERROR_URN],
            "status": self.status.code.to_string(),
            "detail": self.detail,
        });
        if let Some(scim_type) = self.scim_type {
            body["scimType"] = json!(scim_type);
        }
        body.to_string()
    }
}

pub fn scim_content_type() -> ContentType {
    ContentType::new("application", "scim+json")
}

impl Responder<'_, 'static> for ScimError {
    fn respond_to(self, _: &Request<'_>) -> response::Result<'static> {
        let body = self.body();
        let mut builder = Response::build();
        builder.status(self.status).header(scim_content_type());
        if let Some(seconds) = self.retry_after {
            builder.raw_header("Retry-After", seconds.to_string());
        }
        builder.sized_body(Some(body.len()), Cursor::new(body)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(error: &ScimError) -> serde_json::Value {
        serde_json::from_str(&error.body()).expect("the SCIM error body must be valid JSON")
    }

    #[test]
    fn every_error_is_a_well_formed_scim_envelope() {
        // RFC 7644 section 3.12: schemas, status as a STRING, optional scimType.
        let cases = [
            ScimError::unauthorized(),
            ScimError::not_found(),
            ScimError::internal(),
            ScimError::payload_too_large(),
            ScimError::too_many_requests(),
            ScimError::not_implemented("groups off"),
            ScimError::bad_request("invalidValue", "bad"),
            ScimError::conflict("uniqueness", "dup"),
            ScimError::from_status(Status::ServiceUnavailable),
            ScimError::from_status(Status::MethodNotAllowed),
        ];
        for error in cases {
            let body = body_of(&error);
            assert_eq!(body["schemas"][0], json!(SCIM_ERROR_URN), "{:?}", error.status);
            assert!(body["status"].is_string(), "status must be a string, not a number: {:?}", error.status);
            assert_eq!(body["status"], json!(error.status.code.to_string()));
            assert!(body["detail"].as_str().is_some_and(|d| !d.is_empty()), "{:?}", error.status);
        }
    }

    #[test]
    fn only_429_carries_retry_after() {
        // A throttled client needs somewhere to start backing off from; every
        // other status would be meaningless with one.
        // Asserted as an observable property, not by re-deriving the value from
        // the same expression that produced it (which could never fail), and not
        // against a literal 1 (which only held because the test environment pins
        // SCIM_RATELIMIT_SECONDS=1 and broke under the config matrix).
        let configured = crate::CONFIG.scim_ratelimit_seconds().max(1);
        for error in [ScimError::too_many_requests(), ScimError::from_status(Status::TooManyRequests)] {
            let seconds = error.retry_after.expect("a 429 must carry Retry-After");
            assert!(seconds >= 1, "Retry-After must be a usable delay, got {seconds}");
            assert_eq!(seconds, configured, "Retry-After must follow SCIM_RATELIMIT_SECONDS");
        }
        for error in
            [ScimError::unauthorized(), ScimError::internal(), ScimError::from_status(Status::ServiceUnavailable)]
        {
            assert_eq!(error.retry_after, None, "{:?} must not carry Retry-After", error.status);
        }
    }

    #[test]
    fn scim_type_appears_only_where_the_rfc_defines_it() {
        // scimType is defined for 400; 409 + uniqueness is the one sanctioned
        // pairing outside it. Anything else must omit the key entirely.
        assert_eq!(body_of(&ScimError::bad_request("invalidPath", "x"))["scimType"], json!("invalidPath"));
        assert_eq!(body_of(&ScimError::conflict("uniqueness", "x"))["scimType"], json!("uniqueness"));
        for error in [ScimError::unauthorized(), ScimError::not_found(), ScimError::internal()] {
            assert_eq!(body_of(&error).get("scimType"), None, "{:?} must omit scimType", error.status);
        }
    }

    #[test]
    fn from_status_never_leaks_request_content() {
        // The default catcher runs on statuses we did not construct, so its
        // detail must come from Rocket's reason phrase and nothing else.
        for status in [Status::ServiceUnavailable, Status::MethodNotAllowed, Status::NotAcceptable] {
            let detail = ScimError::from_status(status).detail;
            assert_eq!(detail, status.reason().unwrap_or("Request failed"));
        }
    }
}
