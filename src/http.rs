//! The one door to the network. Every client sends through a [`Transport`],
//! so an app can supply its own, and tests hand in a fake that never leaves
//! the process.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::Error;

/// A boxed, sendable future: what the crate's traits return, so they can be
/// used as trait objects.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn new(method: &str, url: impl Into<String>) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> HttpRequest {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// A JSON body, with its content type.
    pub fn json(self, body: &impl Serialize) -> HttpRequest {
        let mut r = self.header("Content-Type", "application/json");
        r.body = serde_json::to_vec(body).unwrap_or_default();
        r
    }

    /// A form body (`application/x-www-form-urlencoded`), as OAuth wants.
    pub fn form(self, fields: &[(&str, &str)]) -> HttpRequest {
        let mut r = self.header("Content-Type", "application/x-www-form-urlencoded");
        r.body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish()
            .into_bytes();
        r
    }

    /// The first value of a header, by case-insensitive name.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// The body as JSON.
    pub fn json_body(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// The form fields of the body.
    pub fn form_fields(&self) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&self.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }
}

/// One HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> HttpResponse {
        HttpResponse {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// A JSON response.
    pub fn json(status: u16, body: &serde_json::Value) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(body).unwrap_or_default(),
        }
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// The body as a JSON value; `Null` when it isn't JSON.
    pub fn value(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// The body as `T`, or a `bad_response` error.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, Error> {
        serde_json::from_slice(&self.body).map_err(|e| {
            Error::new(
                Some(self.status),
                "bad_response",
                format!("Unexpected response: {e}"),
            )
        })
    }

    /// The server's `error` code, if the body carries one.
    pub fn error_code(&self) -> Option<String> {
        self.value().get("error")?.as_str().map(str::to_string)
    }
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Sends requests. A transport error (no network, DNS, TLS, timeout) is
/// returned as an [`Error`] with code `network`; any HTTP status, including
/// 4xx and 5xx, is a response.
pub trait Transport: Send + Sync {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>>;
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
        (**self).send(request)
    }
}

/// The default transport, on reqwest with rustls.
#[cfg(feature = "reqwest")]
#[derive(Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "reqwest")]
impl ReqwestTransport {
    /// A client with a 30-second timeout.
    pub fn new() -> ReqwestTransport {
        ReqwestTransport {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Wraps a client the app configured itself.
    pub fn with_client(client: reqwest::Client) -> ReqwestTransport {
        ReqwestTransport { client }
    }
}

#[cfg(feature = "reqwest")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "reqwest")]
impl Transport for ReqwestTransport {
    fn send(&self, request: HttpRequest) -> BoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async move {
            let method = reqwest::Method::from_bytes(request.method.as_bytes())
                .map_err(|_| Error::new(None, "bad_request", "Unknown HTTP method."))?;
            let mut builder = self.client.request(method, &request.url);
            for (k, v) in &request.headers {
                builder = builder.header(k, v);
            }
            if !request.body.is_empty() {
                builder = builder.body(request.body);
            }
            let response = builder.send().await.map_err(Error::network)?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
                .collect();
            let body = response.bytes().await.map_err(Error::network)?.to_vec();
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}

/// Unix seconds now.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Percent-encodes one path segment.
pub(crate) fn segment(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
}

/// `base` with `query` appended.
pub(crate) fn with_query(base: &str, query: &[(&str, &str)]) -> String {
    if query.is_empty() {
        return base.to_string();
    }
    let q = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    format!("{base}?{q}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_and_queries_are_encoded() {
        let r = HttpRequest::new("POST", "https://x.test").form(&[("a", "1 2"), ("b", "&")]);
        assert_eq!(String::from_utf8(r.body.clone()).unwrap(), "a=1+2&b=%26");
        assert_eq!(r.form_fields()[0], ("a".into(), "1 2".into()));
        assert_eq!(
            r.header_value("content-type"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(
            with_query("https://x.test/p", &[("k", "a b")]),
            "https://x.test/p?k=a+b"
        );
        assert_eq!(segment("a b/c"), "a%20b%2Fc");
    }
}
