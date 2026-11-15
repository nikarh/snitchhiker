//! Firebase Cloud Messaging, HTTP v1: high-priority data messages to the Play build of the app, with the user's own
//! Firebase project's service account (plan §8.5). The account's key signs a JWT (RS256) exchanged for an access
//! token, kept until shortly before it expires.

use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use tokio::sync::Mutex;

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// The fields of a service account key file used here.
#[derive(Deserialize)]
struct Account {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the FCM service account {0}: {1}")]
    Account(String, String),
    #[error("FCM: {0}")]
    Send(String),
}

pub struct Fcm {
    project: String,
    email: String,
    token_uri: String,
    key: RsaKeyPair,
    /// Where messages are sent (`https://fcm.googleapis.com`; another for tests).
    api: String,
    token: Mutex<Option<(String, Instant)>>,
}

/// The DER inside a PEM block.
fn pem_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    STANDARD.decode(body.trim()).ok()
}

impl Fcm {
    pub fn load(path: &Path, api: &str) -> Result<Self, Error> {
        let fail = |e: String| Error::Account(path.display().to_string(), e);
        let text = std::fs::read_to_string(path).map_err(|e| fail(e.to_string()))?;
        let account: Account = serde_json::from_str(&text).map_err(|e| fail(e.to_string()))?;
        let der = pem_der(&account.private_key)
            .ok_or_else(|| fail("private_key isn't PEM".to_owned()))?;
        let key = RsaKeyPair::from_pkcs8(&der).map_err(|e| fail(e.to_string()))?;
        Ok(Self {
            project: account.project_id,
            email: account.client_email,
            token_uri: account.token_uri,
            key,
            api: api.trim_end_matches('/').to_owned(),
            token: Mutex::new(None),
        })
    }

    fn assertion(&self) -> Result<String, Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "iss": self.email,
            "scope": SCOPE,
            "aud": self.token_uri,
            "iat": now,
            "exp": now + 3600,
        });
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signed = format!("{header}.{claims}");
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signed.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::Send("signing the token request".to_owned()))?;
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    async fn access_token(&self, http: &reqwest::Client) -> Result<String, Error> {
        let mut token = self.token.lock().await;
        if let Some((value, until)) = token.as_ref()
            && Instant::now() < *until
        {
            return Ok(value.clone());
        }
        let form = [
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned(),
            ),
            ("assertion", self.assertion()?),
        ];
        let body = form
            .iter()
            .map(|(k, v)| format!("{k}={}", urlencode(v)))
            .collect::<Vec<_>>()
            .join("&");
        let granted: Granted = http
            .post(&self.token_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| Error::Send(format!("the access token: {e}")))?
            .json()
            .await
            .map_err(|e| Error::Send(format!("the access token: {e}")))?;
        // Renewed a minute early.
        let until = Instant::now() + Duration::from_secs(granted.expires_in.saturating_sub(60));
        *token = Some((granted.access_token.clone(), until));
        Ok(granted.access_token)
    }

    /// Sends `payload` (an encoded `PushMessage`) to a device's registration token, as a high-priority data message.
    pub async fn send(
        &self,
        http: &reqwest::Client,
        token: &str,
        payload: &[u8],
    ) -> Result<(), Error> {
        let access = self.access_token(http).await?;
        let message = serde_json::json!({
            "message": {
                "token": token,
                "data": { "m": STANDARD.encode(payload) },
                "android": { "priority": "high" },
            }
        });
        http.post(format!(
            "{}/v1/projects/{}/messages:send",
            self.api, self.project
        ))
        .bearer_auth(access)
        .json(&message)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Error::Send(e.to_string()))?;
        Ok(())
    }
}

/// The token endpoint's answer.
#[derive(Deserialize)]
struct Granted {
    access_token: String,
    expires_in: u64,
}

/// Percent-encodes a form value.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_values_are_percent_encoded() {
        assert_eq!(urlencode("a b/c:d"), "a%20b%2Fc%3Ad");
        assert_eq!(urlencode("abc.DEF-_~"), "abc.DEF-_~");
    }

    #[test]
    fn pem_bodies_are_decoded() {
        assert_eq!(
            pem_der("-----BEGIN PRIVATE KEY-----\nAAEC\n-----END PRIVATE KEY-----\n"),
            Some(vec![0, 1, 2])
        );
    }
}
