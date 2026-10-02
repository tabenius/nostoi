//! Network compartment's small S3 client, enough to anchor a chain head.
//!
//! Nostoi deliberately does not take the AWS SDK as a dependency: this crate
//! keeps its tree small, and the whole surface an anchor needs is one signed
//! `PutObject` (plus `GetObjectRetention` to confirm the lock). So the request
//! is built and signed here, using [Signature Version 4][sigv4], and sent with
//! [`ureq`].
//!
//! [sigv4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv4.html
//!
//! The same code talks to AWS S3 and to Cloudflare R2. The one place they
//! differ matters for anchoring:
//!
//! * **AWS S3 Object Lock** is set per object, with `x-amz-object-lock-mode`
//!   and `x-amz-object-lock-retain-until-date`. AWS requires a checksum header
//!   alongside a retention period, so `x-amz-sdk-checksum-algorithm: SHA256`
//!   and `x-amz-checksum-sha256` are sent with it. In `COMPLIANCE` mode no
//!   user, not even the account root, can overwrite or delete the object or
//!   shorten its retention.
//! * **Cloudflare R2 does not support Object Lock** (the S3 API compatibility
//!   table marks `x-amz-object-lock-*` unsupported on `PutObject`, and
//!   `x-amz-bucket-object-lock-enabled: true` is rejected). R2 instead has
//!   *bucket locks*: prefix rules with an age/date/indefinite condition, set
//!   through the Cloudflare API, that apply to new and existing objects and
//!   cannot be overridden by the S3 token.
//!
//! So an anchor to R2 stores an immutable, uniquely named object under a
//! prefix, and the retention is enforced by the bucket lock rule on that
//! prefix — configured out of band, not by this client. [`Provider`] records
//! which of the two applies so the caller can fail rather than silently write
//! unless it is told locking is handled.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, UtcOffset};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;

/// Which object-locking model the target offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// AWS S3: per-object Object Lock via `PutObject` headers.
    S3,
    /// Cloudflare R2: no object lock; a bucket lock rule on the prefix.
    R2,
}

/// Check that an endpoint is usable, without needing credentials.
///
/// Configuration is validated before any destination is contacted, so a typo in
/// a target file is reported up front rather than as one rejected destination
/// among several.
pub fn check_endpoint(endpoint: &str) -> Result<()> {
    split_endpoint(endpoint).map(|_| ())
}

impl Provider {
    /// Guess from the endpoint host. R2 endpoints are
    /// `<account>.r2.cloudflarestorage.com`.
    pub fn detect(endpoint: &str) -> Provider {
        let host = endpoint
            .split_once("://")
            .map_or(endpoint, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("");
        if host.ends_with(".r2.cloudflarestorage.com") {
            Provider::R2
        } else {
            Provider::S3
        }
    }
}

/// Object Lock retention mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockMode {
    /// Can be bypassed by a caller with `s3:BypassGovernanceRetention`.
    Governance,
    /// Cannot be bypassed by anyone, including the account root.
    Compliance,
}

impl LockMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            LockMode::Governance => "GOVERNANCE",
            LockMode::Compliance => "COMPLIANCE",
        }
    }
}

/// A requested object lock.
#[derive(Clone, Debug)]
pub struct ObjectLock {
    pub mode: LockMode,
    pub retain_until: OffsetDateTime,
}

/// An S3 access key and secret, with an optional session token.
#[derive(Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
}

impl Credentials {
    /// Read the standard AWS environment variables:
    /// `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`.
    pub fn from_env() -> Result<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| Error::S3("AWS_ACCESS_KEY_ID is not set".into()))?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| Error::S3("AWS_SECRET_ACCESS_KEY is not set".into()))?;
        Ok(Self {
            access_key,
            secret_key,
            session_token: std::env::var("AWS_SESSION_TOKEN")
                .ok()
                .filter(|t| !t.is_empty()),
        })
    }
}

/// A configured S3/R2 client.
pub struct Client {
    scheme: String,
    /// Endpoint authority, host plus `:port` when the URL carries one.
    host: String,
    bucket: String,
    region: String,
    path_style: bool,
    credentials: Credentials,
    agent: ureq::Agent,
    signing_clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

/// What to send with a `PutObject`.
pub struct PutOptions {
    pub content_type: String,
    /// Object Lock headers (AWS S3 only; callers must not set these on R2).
    pub lock: Option<ObjectLock>,
    /// Refuse to overwrite an existing key with `If-None-Match: *`.
    pub only_if_absent: bool,
}

/// The result of a successful `PutObject`.
pub struct PutResult {
    pub etag: Option<String>,
    /// A conditional upload found an existing object; caller must verify it.
    pub existed: bool,
}

/// An object's retention, as read back from S3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retention {
    pub mode: String,
    pub retain_until: String,
}

impl Client {
    /// Non-secret identity of the destination, including addressing semantics.
    pub fn target_identity(&self) -> String {
        serde_json::json!({
            "endpoint": format!("{}://{}", self.scheme, self.host),
            "bucket": self.bucket, "region": self.region, "path_style": self.path_style,
        })
        .to_string()
    }
    /// Build a client for `endpoint` (for example
    /// `https://<account>.r2.cloudflarestorage.com` or
    /// `https://s3.us-west-2.amazonaws.com`).
    pub fn new(
        endpoint: &str,
        bucket: &str,
        region: &str,
        path_style: bool,
        credentials: Credentials,
    ) -> Result<Self> {
        let (scheme, host) = split_endpoint(endpoint)?;
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .new_agent();
        Ok(Self {
            scheme,
            host,
            bucket: bucket.to_string(),
            region: region.to_string(),
            path_style,
            credentials,
            agent,
            signing_clock: Arc::new(OffsetDateTime::now_utc),
        })
    }

    /// Set the clock used for Signature Version 4 timestamps.
    ///
    /// Defaults to [`OffsetDateTime::now_utc`]. The clock is called once for
    /// each send attempt, including retries, and its value is normalized to UTC.
    pub fn with_signing_clock<F>(mut self, clock: F) -> Self
    where
        F: Fn() -> OffsetDateTime + Send + Sync + 'static,
    {
        self.signing_clock = Arc::new(clock);
        self
    }

    /// Upload `body` to `key`, optionally under an Object Lock.
    pub fn put_object(&self, key: &str, body: &[u8], options: &PutOptions) -> Result<PutResult> {
        let mut headers = vec![("content-type".to_string(), options.content_type.clone())];
        if options.only_if_absent {
            headers.push(("if-none-match".to_string(), "*".to_string()));
        }
        if let Some(lock) = &options.lock {
            let retain = lock
                .retain_until
                .to_offset(UtcOffset::UTC)
                .format(&Rfc3339)
                .map_err(|error| Error::S3(format!("retain-until: {error}")))?;
            // AWS requires a checksum when a retention period is set.
            let checksum = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
            headers.push((
                "x-amz-object-lock-mode".to_string(),
                lock.mode.as_str().to_string(),
            ));
            headers.push(("x-amz-object-lock-retain-until-date".to_string(), retain));
            headers.push((
                "x-amz-sdk-checksum-algorithm".to_string(),
                "SHA256".to_string(),
            ));
            headers.push(("x-amz-checksum-sha256".to_string(), checksum));
        }
        let response = self
            .send("PUT", key, "", "", headers, body)
            .map_err(|error| Error::UploadUncertain {
                key: key.into(),
                detail: error.to_string(),
            })?;
        // If-None-Match: * and key exists -> 412 Precondition Failed
        if options.only_if_absent && response.status == 412 {
            return Ok(PutResult {
                etag: None,
                existed: true,
            });
        }
        if !(200..=299).contains(&response.status) {
            if response.uncertain || matches!(response.status, 500 | 502 | 503 | 504) {
                return Err(Error::UploadUncertain {
                    key: key.into(),
                    detail: format!(
                        "{}; after an ambiguous attempt",
                        self.failure("PutObject", &response)
                    ),
                });
            }
            return Err(Error::S3(self.failure("PutObject", &response)));
        }
        Ok(PutResult {
            etag: response.header("etag"),
            existed: false,
        })
    }

    /// Read an anchor object for conditional-upload reconciliation.
    pub fn get_object(&self, key: &str) -> Result<String> {
        let response = self.send("GET", key, "", "", vec![], &[])?;
        if response.status != 200 {
            return Err(Error::S3(self.failure("GetObject", &response)));
        }
        Ok(response.body)
    }

    /// Read back an object's Object Lock retention, or `None` if the object has
    /// none or does not exist. AWS S3 only; R2 does not implement this.
    pub fn get_object_retention(&self, key: &str) -> Result<Option<Retention>> {
        let response = self.send("GET", key, "retention", "retention=", vec![], &[])?;
        if response.status == 404 {
            return Ok(None);
        }
        if response.status != 200 {
            return Err(Error::S3(self.failure("GetObjectRetention", &response)));
        }
        Ok(parse_retention(&response.body))
    }

    /// Sign and send one request.
    fn send(
        &self,
        method: &str,
        key: &str,
        raw_query: &str,
        canonical_query: &str,
        headers: Vec<(String, String)>,
        body: &[u8],
    ) -> Result<Response> {
        let (url, host, canonical_uri) = self.target(key, raw_query);
        let payload_hash = sha256_hex(body);
        let retryable = method == "GET"
            || headers
                .iter()
                .any(|(name, value)| name == "if-none-match" && value == "*");
        let mut attempt = 0;
        let mut uncertain = false;
        let (response, signed_time) = loop {
            let (authorization, signed_headers) = self.sign_request(
                method,
                &host,
                &canonical_uri,
                canonical_query,
                &payload_hash,
                headers.clone(),
            )?;
            // ureq sets Host from the URL; signing it is enough.
            let send_headers: Vec<(&str, &str)> = signed_headers
                .iter()
                .filter(|(name, _)| !name.eq_ignore_ascii_case("host"))
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let response = match method {
                "PUT" => {
                    let mut request = self.agent.put(&url);
                    for (name, value) in &send_headers {
                        request = request.header(*name, *value);
                    }
                    request.header("Authorization", &authorization).send(body)
                }
                "GET" => {
                    let mut request = self.agent.get(&url);
                    for (name, value) in &send_headers {
                        request = request.header(*name, *value);
                    }
                    request.header("Authorization", &authorization).call()
                }
                "HEAD" => {
                    let mut request = self.agent.head(&url);
                    for (name, value) in &send_headers {
                        request = request.header(*name, *value);
                    }
                    request.header("Authorization", &authorization).call()
                }
                other => return Err(Error::S3(format!("unsupported method {other}"))),
            };
            let transient = match &response {
                Ok(response) => matches!(response.status().as_u16(), 429 | 500 | 502 | 503 | 504),
                Err(_) => true,
            };
            if method == "PUT"
                && (response.is_err()
                    || response
                        .as_ref()
                        .is_ok_and(|r| matches!(r.status().as_u16(), 500 | 502 | 503 | 504)))
            {
                uncertain = true;
            }
            if retryable && transient && attempt < 2 {
                std::thread::sleep(Duration::from_millis(100 << attempt));
                attempt += 1;
                continue;
            }
            let signed_time = signed_headers
                .iter()
                .find(|(name, _)| name == "x-amz-date")
                .and_then(|(_, value)| parse_signed_time(value));
            break (response, signed_time);
        };

        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let mut collected = Vec::new();
                for (name, value) in response.headers() {
                    collected.push((
                        name.as_str().to_string(),
                        value.to_str().unwrap_or_default().to_string(),
                    ));
                }
                let body = if (200..=299).contains(&status) {
                    response.into_body().read_to_string()
                        .map_err(|_| Error::S3("response body could not be read".into()))?
                } else {
                    // Error bodies are untrusted, potentially reflective and arbitrarily large.
                    let mut bytes = Vec::new();
                    let read = response.into_body().as_reader().take(16 * 1024 + 1)
                        .read_to_end(&mut bytes);
                    if read.is_ok() && bytes.len() <= 16 * 1024 {
                        String::from_utf8(bytes).unwrap_or_default()
                    } else {
                        String::new()
                    }
                };
                Ok(Response {
                    status,
                    body,
                    headers: collected,
                    uncertain,
                    signed_time,
                })
            }
            Err(ureq::Error::StatusCode(status)) => Ok(Response {
                status,
                body: String::new(),
                headers: Vec::new(),
                uncertain,
                signed_time,
            }),
            Err(_) => Err(Error::S3("transport failed; no definitive HTTP response (check connectivity, endpoint and TLS)".into())),
        }
    }

    fn failure(&self, operation: &str, response: &Response) -> String {
        let field = |name| error_field(&response.body, name);
        // Only recognized codes are rendered: even a syntactically valid Code can echo secrets.
        let code = field("Code").unwrap_or_default();
        let hint = match code.as_str() {
            "RequestTimeTooSkewed" | "RequestExpired" => "synchronize the host clock and check its UTC time",
            "SignatureDoesNotMatch" => "check signing credentials, endpoint, region and signed headers; also synchronize the host clock",
            "ExpiredToken" | "InvalidToken" => "refresh the session credentials/token",
            "AccessDenied" => "check credentials, bucket policy and required permissions",
            "NoSuchKey" => "check the object key and destination bucket",
            "NoSuchBucket" => "check the destination bucket and endpoint",
            "AuthorizationHeaderMalformed" | "PermanentRedirect" | "IncorrectEndpoint" | "IllegalLocationConstraintException" => "check the bucket region and endpoint (R2 uses region auto)",
            "SlowDown" | "ServiceUnavailable" | "InternalError" => "service temporarily unavailable; retry later",
            _ => match response.status {
                301 | 307 => "check the bucket region and endpoint",
                401 | 403 => "check credentials and required permissions",
                404 => "check the object key and destination bucket",
                429 | 500 | 502 | 503 | 504 => "service temporarily unavailable; retry later",
                _ => "check the endpoint and request configuration",
            },
        };
        let recognized = matches!(
            code.as_str(),
            "RequestTimeTooSkewed"
                | "RequestExpired"
                | "SignatureDoesNotMatch"
                | "ExpiredToken"
                | "InvalidToken"
                | "AccessDenied"
                | "NoSuchKey"
                | "NoSuchBucket"
                | "AuthorizationHeaderMalformed"
                | "PermanentRedirect"
                | "IncorrectEndpoint"
                | "IllegalLocationConstraintException"
                | "SlowDown"
                | "ServiceUnavailable"
                | "InternalError"
        );
        let mut detail = format!("{operation} returned {}", response.status);
        if recognized && !self.contains_credential(&code) {
            detail.push_str(&format!("; code={code}"));
        }
        for (label, value) in [
            (
                "request-id",
                response
                    .header("x-amz-request-id")
                    .or_else(|| field("RequestId")),
            ),
            (
                "host-id",
                response.header("x-amz-id-2").or_else(|| field("HostId")),
            ),
            (
                "bucket-region",
                response
                    .header("x-amz-bucket-region")
                    .or_else(|| field("Region")),
            ),
        ] {
            if let Some(value) = value.filter(|v| self.safe_metadata(v)) {
                detail.push_str(&format!("; {label}={value}"));
            }
        }
        // RequestTime is only corroboration; never use a remote echo as the local clock.
        let request_matches = field("RequestTime").is_none_or(|value| {
            parse_server_time(&value).or_else(|| parse_signed_time(&value)) == response.signed_time
        });
        let server = field("ServerTime")
            .and_then(|v| parse_server_time(&v))
            .or_else(|| {
                response.header("date").and_then(|v| {
                    OffsetDateTime::parse(&v, &time::format_description::well_known::Rfc2822).ok()
                })
            });
        if let (Some(server), Some(signed)) = (server, response.signed_time) {
            if request_matches {
                let seconds = signed.unix_timestamp() - server.unix_timestamp();
                let direction = if seconds < 0 {
                    "behind"
                } else if seconds > 0 {
                    "ahead"
                } else {
                    "aligned"
                };
                detail.push_str(&format!("; estimated clock skew: {} seconds {direction} of server (approximate, server-reported); synchronize the host clock", seconds.unsigned_abs()));
            }
        }
        detail.push_str(&format!("; {hint}"));
        detail
    }

    fn safe_metadata(&self, value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.+/=".contains(&b))
            && !self.contains_credential(value)
            && !["authorization", "credential", "signature", "security-token"]
                .iter()
                .any(|word| value.to_ascii_lowercase().contains(word))
    }

    fn contains_credential(&self, value: &str) -> bool {
        [
            Some(self.credentials.access_key.as_str()),
            Some(self.credentials.secret_key.as_str()),
            self.credentials.session_token.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|secret| !secret.is_empty() && value.contains(secret))
    }

    /// Build fresh signing headers for one send attempt.
    fn sign_request(
        &self,
        method: &str,
        host: &str,
        canonical_uri: &str,
        canonical_query: &str,
        payload_hash: &str,
        mut headers: Vec<(String, String)>,
    ) -> Result<(String, Vec<(String, String)>)> {
        let now = (self.signing_clock)();
        let amz_date = format_amz_date(&now)?;
        let date = format_amz_day(&now)?;

        headers.push(("host".to_string(), host.to_string()));
        headers.push(("x-amz-content-sha256".to_string(), payload_hash.to_string()));
        headers.push(("x-amz-date".to_string(), amz_date.clone()));
        if let Some(token) = &self.credentials.session_token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }

        Ok(sign(SigningInput {
            credentials: &self.credentials,
            region: &self.region,
            service: "s3",
            amz_date: &amz_date,
            date: &date,
            method,
            canonical_uri,
            canonical_query,
            headers: &headers,
            payload_hash,
        }))
    }

    /// The URL, the `Host` header value, and the canonical URI for `key`.
    fn target(&self, key: &str, raw_query: &str) -> (String, String, String) {
        let encoded = encode_path(key);
        let (host, canonical_uri) = if self.path_style {
            (self.host.clone(), format!("/{}/{}", self.bucket, encoded))
        } else {
            (
                format!("{}.{}", self.bucket, self.host),
                format!("/{}", encoded),
            )
        };
        let mut url = format!("{}://{}{}", self.scheme, host, canonical_uri);
        if !raw_query.is_empty() {
            url.push('?');
            url.push_str(raw_query);
        }
        (url, host, canonical_uri)
    }
}

/// The result of a raw request: status, body and headers.
struct Response {
    status: u16,
    body: String,
    headers: Vec<(String, String)>,
    uncertain: bool,
    signed_time: Option<OffsetDateTime>,
}

fn parse_signed_time(value: &str) -> Option<OffsetDateTime> {
    time::PrimitiveDateTime::parse(
        value,
        format_description!("[year][month][day]T[hour][minute][second]Z"),
    )
    .ok()
    .map(|v| v.assume_utc())
}

fn parse_server_time(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339).ok()
}

/// Deliberately narrow XML recognizer: direct text children of Error, including
/// namespace prefixes. No entities, DTDs, CDATA or nested reflective content.
/// Unsupported/malformed documents simply provide no diagnostic fields.
fn error_field(xml: &str, wanted: &str) -> Option<String> {
    if xml.len() > 16 * 1024 {
        return None;
    }
    let mut stack: Vec<&str> = Vec::new();
    let mut rest = xml;
    let mut found = None;
    let mut text = "";
    let mut root_seen = false;
    while let Some(start) = rest.find('<') {
        let preceding = &rest[..start];
        if stack.len() == 2 && stack[1].rsplit(':').next() == Some(wanted) {
            text = preceding.trim();
        } else if stack.len() != 2 && !preceding.trim().is_empty() {
            return None;
        }
        rest = &rest[start..];
        if rest.starts_with("<?xml ") && stack.is_empty() {
            rest = &rest[rest.find("?>")? + 2..];
            continue;
        }
        let end = rest.find('>')?;
        let tag = &rest[1..end];
        if let Some(close) = tag.strip_prefix('/') {
            let open = stack.pop()?;
            if close != open {
                return None;
            }
            if stack.len() == 1 && open.rsplit(':').next() == Some(wanted) {
                if found.is_some() || text.contains('&') || text.len() > 128 {
                    return None;
                }
                found = Some(text.to_string());
            }
        } else {
            let name = tag.split_whitespace().next()?;
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_:.-".contains(&b))
                || stack.len() >= 2
            {
                return None;
            }
            if stack.is_empty() {
                if root_seen || name.rsplit(':').next() != Some("Error") {
                    return None;
                }
                root_seen = true;
            }
            stack.push(name);
        }
        rest = &rest[end + 1..];
    }
    if stack.is_empty() && rest.trim().is_empty() {
        found
    } else {
        None
    }
}

impl Response {
    fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}

/// Everything needed to sign one request.
struct SigningInput<'a> {
    credentials: &'a Credentials,
    region: &'a str,
    service: &'a str,
    amz_date: &'a str,
    date: &'a str,
    method: &'a str,
    canonical_uri: &'a str,
    canonical_query: &'a str,
    headers: &'a [(String, String)],
    payload_hash: &'a str,
}

/// Sign a request, returning the `Authorization` value and the headers to send.
///
/// Split out from [`Client::send`] so the signing can be tested on its own.
fn sign(input: SigningInput<'_>) -> (String, Vec<(String, String)>) {
    let (canonical_headers, signed_header_names) = canonical_headers(input.headers);
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        input.canonical_uri,
        input.canonical_query,
        canonical_headers,
        signed_header_names,
        input.payload_hash,
    );
    let scope = format!(
        "{}/{}/{}/aws4_request",
        input.date, input.region, input.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        input.amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes()),
    );
    let key = signing_key(
        &input.credentials.secret_key,
        input.date,
        input.region,
        input.service,
    );
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        input.credentials.access_key, scope, signed_header_names, signature,
    );
    (authorization, input.headers.to_vec())
}

/// Canonical headers (lowercased, sorted, trimmed) and the signed-header list.
fn canonical_headers(headers: &[(String, String)]) -> (String, String) {
    let mut sorted: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_ascii_lowercase(),
                value.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut block = String::new();
    let mut names = Vec::with_capacity(sorted.len());
    for (name, value) in &sorted {
        block.push_str(name);
        block.push(':');
        block.push_str(value);
        block.push('\n');
        names.push(name.clone());
    }
    (block, names.join(";"))
}

/// The SigV4 signing key: HMAC chain over date, region, service and terminator.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let initial = format!("AWS4{secret}");
    let key = hmac(initial.as_bytes(), date.as_bytes());
    let key = hmac(&key, region.as_bytes());
    let key = hmac(&key, service.as_bytes());
    hmac(&key, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn format_amz_date(now: &OffsetDateTime) -> Result<String> {
    let format = format_description!("[year][month][day]T[hour][minute][second]Z");
    now.to_offset(UtcOffset::UTC)
        .format(&format)
        .map_err(|error| Error::S3(format!("amz-date: {error}")))
}

fn format_amz_day(now: &OffsetDateTime) -> Result<String> {
    let format = format_description!("[year][month][day]");
    now.to_offset(UtcOffset::UTC)
        .format(&format)
        .map_err(|error| Error::S3(format!("date: {error}")))
}

/// Split `https://host:port/...` into `("https", "host:port")`.
fn split_endpoint(endpoint: &str) -> Result<(String, String)> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| Error::S3(format!("endpoint has no scheme: {endpoint}")))?;
    if scheme != "https" && scheme != "http" {
        return Err(Error::S3(format!("unsupported scheme: {scheme}")));
    }
    let authority = rest.split('/').next().unwrap_or("");
    if authority.contains(['@', '?', '#']) || authority.chars().any(char::is_control) {
        return Err(Error::S3(
            "endpoint authority must not contain credentials, query or fragment".into(),
        ));
    }
    if authority.is_empty() {
        return Err(Error::S3(format!("endpoint has no host: {endpoint}")));
    }
    Ok((scheme.to_string(), authority.to_string()))
}

/// Percent-encode a key as an S3 path, keeping `/` separators.
fn encode_path(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for byte in key.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Pull `Mode` and `RetainUntilDate` out of a `GetObjectRetention` response.
fn parse_retention(xml: &str) -> Option<Retention> {
    Some(Retention {
        mode: element(xml, "Mode")?,
        retain_until: element(xml, "RetainUntilDate")?,
    })
}

fn element(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    Some(xml[start..end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_credentials() -> Credentials {
        Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    #[test]
    fn injected_signing_clock_has_deterministic_utc_timestamp_and_signature() {
        let client = Client::new(
            "https://s3.amazonaws.com",
            "bucket",
            "us-east-1",
            true,
            example_credentials(),
        )
        .unwrap()
        .with_signing_clock(|| time::macros::datetime!(2015-08-31 01:59:59 +02:00));
        let (authorization, headers) = client
            .sign_request(
                "GET",
                "s3.amazonaws.com",
                "/bucket/key",
                "",
                &sha256_hex(b""),
                vec![],
            )
            .unwrap();
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name == "x-amz-date")
                .unwrap()
                .1,
            "20150830T235959Z"
        );
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
             Signature=3ddf05fa0a32eab23c4a59d783436786ccbfd83d7898d1b2880bfdd107022a06"
        );
    }

    #[test]
    fn retries_sign_afresh_with_the_injected_clock() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};

        for method in ["GET", "PUT"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let host = listener.local_addr().unwrap().to_string();
            let server = std::thread::spawn(move || {
                let mut requests = Vec::new();
                for status in ["503 Service Unavailable", "429 Too Many Requests", "200 OK"] {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(&mut stream);
                    let mut request = String::new();
                    loop {
                        let mut line = String::new();
                        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                        if line == "\r\n" {
                            break;
                        }
                        request.push_str(&line);
                    }
                    requests.push(request);
                    write!(
                        stream,
                        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                }
                requests
            });
            let calls = Arc::new(AtomicUsize::new(0));
            let clock_calls = Arc::clone(&calls);
            let start = time::macros::datetime!(2015-08-30 23:59:59 UTC);
            let client = Client::new(
                &format!("http://{host}"),
                "bucket",
                "us-east-1",
                true,
                example_credentials(),
            )
            .unwrap()
            .with_signing_clock(move || {
                start + time::Duration::seconds(clock_calls.fetch_add(1, Ordering::SeqCst) as i64)
            });
            let headers = if method == "PUT" {
                vec![("if-none-match".to_string(), "*".to_string())]
            } else {
                vec![]
            };
            assert_eq!(
                client
                    .send(method, "key", "", "", headers.clone(), &[])
                    .unwrap()
                    .status,
                200
            );
            let requests = server.join().unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 3);
            for (attempt, request) in requests.iter().enumerate() {
                let now = start + time::Duration::seconds(attempt as i64);
                let amz_date = format_amz_date(&now).unwrap();
                let date = format_amz_day(&now).unwrap();
                let payload_hash = sha256_hex(b"");
                let mut expected_headers = headers.clone();
                expected_headers.extend([
                    ("host".to_string(), host.clone()),
                    ("x-amz-content-sha256".to_string(), payload_hash.clone()),
                    ("x-amz-date".to_string(), amz_date.clone()),
                ]);
                let (expected_authorization, _) = sign(SigningInput {
                    credentials: &example_credentials(),
                    region: "us-east-1",
                    service: "s3",
                    amz_date: &amz_date,
                    date: &date,
                    method,
                    canonical_uri: "/bucket/key",
                    canonical_query: "",
                    headers: &expected_headers,
                    payload_hash: &payload_hash,
                });
                let wire_headers: Vec<_> = request
                    .lines()
                    .skip(1)
                    .map(|line| line.split_once(": ").unwrap())
                    .collect();
                for (name, expected) in [
                    ("x-amz-date", amz_date),
                    ("authorization", expected_authorization),
                ] {
                    let values: Vec<_> = wire_headers
                        .iter()
                        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
                        .map(|(_, value)| *value)
                        .collect();
                    assert_eq!(values, vec![expected.as_str()]);
                }
            }
        }
    }

    #[test]
    fn canonical_headers_sort_and_lowercase() {
        let headers = vec![
            ("X-Amz-Date".to_string(), " 20150830T123600Z ".to_string()),
            ("Host".to_string(), "iam.amazonaws.com".to_string()),
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
        ];
        let (block, names) = canonical_headers(&headers);
        assert_eq!(
            block,
            "content-type:application/x-www-form-urlencoded; charset=utf-8\n\
             host:iam.amazonaws.com\n\
             x-amz-date:20150830T123600Z\n"
        );
        assert_eq!(names, "content-type;host;x-amz-date");
    }

    #[test]
    fn signing_key_matches_the_aws_worked_example() {
        // From "Examples of the complete Version 4 signing process", the
        // derived signing key for the documented secret is a well-known value.
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn signature_matches_the_aws_worked_example() {
        // The complete worked example: GET https://iam.amazonaws.com/ with the
        // documented date, headers and empty payload.
        let credentials = example_credentials();
        let headers = vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let (authorization, _) = sign(SigningInput {
            credentials: &credentials,
            region: "us-east-1",
            service: "iam",
            amz_date: "20150830T123600Z",
            date: "20150830",
            method: "GET",
            canonical_uri: "/",
            canonical_query: "Action=ListUsers&Version=2010-05-08",
            headers: &headers,
            payload_hash: &sha256_hex(b""),
        });
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn path_style_and_virtual_hosted_targets() {
        let mut client = Client::new(
            "https://account.r2.cloudflarestorage.com",
            "bucket",
            "auto",
            true,
            example_credentials(),
        )
        .unwrap();
        let (url, host, uri) = client.target("anchors/a/1.json", "");
        assert_eq!(
            url,
            "https://account.r2.cloudflarestorage.com/bucket/anchors/a/1.json"
        );
        assert_eq!(host, "account.r2.cloudflarestorage.com");
        assert_eq!(uri, "/bucket/anchors/a/1.json");

        client.path_style = false;
        let (url, host, uri) = client.target("anchors/a/1.json", "");
        assert_eq!(
            url,
            "https://bucket.account.r2.cloudflarestorage.com/anchors/a/1.json"
        );
        assert_eq!(host, "bucket.account.r2.cloudflarestorage.com");
        assert_eq!(uri, "/anchors/a/1.json");
    }

    #[test]
    fn retention_xml_is_parsed() {
        let xml = "<?xml version=\"1.0\"?><Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                   <Mode>COMPLIANCE</Mode><RetainUntilDate>2027-01-01T00:00:00.000Z</RetainUntilDate>\
                   </Retention>";
        assert_eq!(
            parse_retention(xml),
            Some(Retention {
                mode: "COMPLIANCE".into(),
                retain_until: "2027-01-01T00:00:00.000Z".into(),
            })
        );
    }

    #[test]
    fn endpoint_splitting() {
        assert_eq!(
            split_endpoint("https://account.r2.cloudflarestorage.com").unwrap(),
            (
                "https".to_string(),
                "account.r2.cloudflarestorage.com".to_string()
            )
        );
        assert_eq!(
            split_endpoint("http://127.0.0.1:9000/base").unwrap(),
            ("http".to_string(), "127.0.0.1:9000".to_string())
        );
        assert!(split_endpoint("account.r2.cloudflarestorage.com").is_err());
    }

    #[test]
    fn provider_detection() {
        assert_eq!(
            Provider::detect("https://abc.r2.cloudflarestorage.com"),
            Provider::R2
        );
        assert_eq!(
            Provider::detect("https://s3.us-west-2.amazonaws.com"),
            Provider::S3
        );
    }
}
