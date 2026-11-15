//! Alerts delivered to a webhook (plan §5.9): each alert, as JSON, sent (an HTTP POST) to `alert_webhook`, signed with
//! `alert_webhook_secret_file`'s secret when there is one (HMAC-SHA256 of the body, in `X-Snitchhiker-Signature:
//! sha256=<hex>`, as GitHub signs its webhooks). Sent from a thread of its own: raising an alert never waits on the
//! network. A delivery that fails is logged, not retried.

use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

use ring::hmac;
use serde::Serialize;
use tracing::{debug, warn};

/// What a webhook receives.
#[derive(Debug, Clone, Serialize)]
pub struct Delivery {
    /// The node's name.
    pub node: String,
    pub id: u64,
    pub time_ms: u64,
    pub kind: String,
    pub title: String,
    pub body: String,
}

/// The webhook's delivery thread, when one is configured.
#[derive(Default)]
pub struct Webhook {
    deliveries: Mutex<Option<Sender<Delivery>>>,
}

impl Webhook {
    /// Starts delivering to `url`, signed with the secret in `secret_file` (trimmed) if given.
    pub fn start(&self, url: &str, secret_file: Option<&std::path::Path>) -> std::io::Result<()> {
        let secret = secret_file
            .map(std::fs::read_to_string)
            .transpose()?
            .map(|s| hmac::Key::new(hmac::HMAC_SHA256, s.trim().as_bytes()));
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(std::io::Error::other)?;
        let (sender, receiver) = channel::<Delivery>();
        let url = url.to_owned();
        std::thread::Builder::new()
            .name("alert-webhook".to_owned())
            .spawn(move || {
                for delivery in receiver {
                    let Ok(body) = serde_json::to_vec(&delivery) else {
                        continue;
                    };
                    let mut request = client
                        .post(&url)
                        .header("content-type", "application/json")
                        .header(
                            "user-agent",
                            concat!("snitchhiker/", env!("CARGO_PKG_VERSION")),
                        );
                    if let Some(key) = &secret {
                        request = request.header("x-snitchhiker-signature", signature(key, &body));
                    }
                    match request
                        .body(body)
                        .send()
                        .and_then(reqwest::blocking::Response::error_for_status)
                    {
                        Ok(_) => debug!(id = delivery.id, "an alert was delivered to the webhook"),
                        Err(error) => {
                            warn!(%error, id = delivery.id, "delivering an alert to the webhook");
                        }
                    }
                }
            })?;
        *self
            .deliveries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
        Ok(())
    }

    /// Queues an alert for delivery (nothing happens without a webhook).
    pub fn deliver(&self, delivery: Delivery) {
        if let Some(sender) = self
            .deliveries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(delivery);
        }
    }
}

/// `sha256=<hex HMAC of body>`.
fn signature(key: &hmac::Key, body: &[u8]) -> String {
    let tag = hmac::sign(key, body);
    let mut text = String::from("sha256=");
    for byte in tag.as_ref() {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_hex_hmac_sha256() {
        // RFC 4231, test case 2.
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"Jefe");
        assert_eq!(
            signature(&key, b"what do ya want for nothing?"),
            "sha256=5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
