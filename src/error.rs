//! One error type for every service, carrying the server's code unchanged so
//! an app can show its own message for each.

use crate::http::HttpResponse;

/// A failed request or flow.
///
/// [`code`](Self::code) is the server's `error` field exactly as sent
/// (`no_seats_available`, `email_not_verified`, `two_factor_required`,
/// `device_id_in_use`, `forbidden`, `bad_signature`, `seat_revoked`,
/// `unauthenticated`, `file_too_large`, `quota_exceeded`, `file_mismatch`,
/// `not_uploaded`, `version_conflict`, …), or one of the client's own:
/// `network` (no response), `http_<status>` (a response with no code),
/// `bad_response`, `no_device_identity`, `token_rejected`, `signed_out`,
/// `state_mismatch`, `no_pending`, `upload_failed`, `download_failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// The HTTP status, when there was a response.
    pub status: Option<u16>,
    pub code: String,
    /// The server's `message` or `error_description`, else a plain default.
    pub message: String,
    /// Seconds from `Retry-After`, on 429.
    pub retry_after: Option<u64>,
    /// The current version on a 409 `version_conflict`.
    pub head_version: Option<i64>,
    /// The most a batch may hold, on 413 `batch_too_large`.
    pub max: Option<usize>,
}

impl Error {
    pub fn new(status: Option<u16>, code: impl Into<String>, message: impl Into<String>) -> Error {
        Error {
            status,
            code: code.into(),
            message: message.into(),
            retry_after: None,
            head_version: None,
            max: None,
        }
    }

    pub(crate) fn network(e: impl std::fmt::Display) -> Error {
        Error::new(None, "network", format!("No connection: {e}"))
    }

    pub(crate) fn no_identity() -> Error {
        Error::new(
            None,
            "no_device_identity",
            "This device has no identity yet.",
        )
    }

    /// Reads `{error, message}` (or OAuth's `error_description`) from a
    /// refused response.
    pub fn from_response(r: &HttpResponse) -> Error {
        let body = r.value();
        let text = |k: &str| body.get(k).and_then(|v| v.as_str()).map(str::to_string);
        let code = text("error").unwrap_or_else(|| format!("http_{}", r.status));
        let message = text("message")
            .or_else(|| text("error_description"))
            .unwrap_or_else(|| format!("Request failed ({}).", r.status));
        Error {
            status: Some(r.status),
            code,
            message,
            retry_after: r
                .header_value("retry-after")
                .and_then(|v| v.trim().parse().ok()),
            head_version: body.pointer("/head/version").and_then(|v| v.as_i64()),
            max: body.get("max").and_then(|v| v.as_u64()).map(|v| v as usize),
        }
    }

    pub fn no_seats(&self) -> bool {
        self.code == "no_seats_available"
    }
    /// The seat was revoked: renewal answers it once and the token is
    /// dropped. The device may activate or claim again afterwards.
    pub fn seat_revoked(&self) -> bool {
        self.code == "seat_revoked"
    }
    /// The key was revoked or refunded: refused everywhere.
    pub fn license_key_disabled(&self) -> bool {
        self.code == "license_key_disabled"
    }
    pub fn unauthenticated(&self) -> bool {
        self.code == "unauthenticated"
    }
    pub fn device_not_activated(&self) -> bool {
        self.code == "unknown_device"
    }
    /// Too many requests: show the message; don't retry automatically.
    pub fn rate_limited(&self) -> bool {
        self.code == "rate_limited"
    }
    /// The device has too many tickets open: point the user to one.
    pub fn too_many_open_tickets(&self) -> bool {
        self.code == "too_many_open_tickets"
    }
    pub fn conflict(&self) -> bool {
        self.code == "version_conflict"
    }
    pub fn not_found(&self) -> bool {
        self.status == Some(404)
    }
    /// No response at all: offline, DNS, TLS or a timeout.
    pub fn offline(&self) -> bool {
        self.code == "network"
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn codes_and_details_come_through_unchanged() {
        let mut r = HttpResponse::json(
            409,
            &json!({"error": "version_conflict", "message": "Stale.", "head": {"version": 7}}),
        );
        r.headers.push(("Retry-After".into(), "12".into()));
        let e = Error::from_response(&r);
        assert_eq!(e.code, "version_conflict");
        assert_eq!(e.message, "Stale.");
        assert_eq!(e.head_version, Some(7));
        assert_eq!(e.retry_after, Some(12));
        assert!(e.conflict());

        let bare = Error::from_response(&HttpResponse::new(502, "oops"));
        assert_eq!(bare.code, "http_502");
        let oauth = Error::from_response(&HttpResponse::json(
            400,
            &json!({"error": "invalid_grant", "error_description": "Expired."}),
        ));
        assert_eq!(
            (oauth.code.as_str(), oauth.message.as_str()),
            ("invalid_grant", "Expired.")
        );
    }
}
