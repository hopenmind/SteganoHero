//! An HTTP backend for an OpenAI-compatible server.
//!
//! It POSTs to a `/v1/chat/completions` endpoint. Its locality is decided by the
//! URL: a `localhost` server (Ollama, LM Studio) is `Local`, so content never
//! leaves the machine and the disclaimer gate exempts it; any other host is
//! `Online`, so the gate requires the disclaimer to be shown first. TLS is
//! enabled, so an online `https://` endpoint works as well as a local one.

use std::time::Duration;

use crate::backend::{BackendError, InferenceBackend, Locality};

/// POSTs to an OpenAI-compatible chat-completions endpoint. Local (Ollama on
/// :11434, LM Studio on :1234) or online, decided by the URL host.
pub struct HttpBackend {
    base_url: String,
    model: String,
    system_prompt: String,
    timeout: Duration,
}

impl HttpBackend {
    /// `base_url` is the server origin, for example `http://localhost:11434` or
    /// `https://api.example.com`.
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        system_prompt: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            system_prompt: system_prompt.into(),
            timeout: Duration::from_secs(60),
        }
    }

    /// Override the per-call timeout (default 60s).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl InferenceBackend for HttpBackend {
    fn rewrite(&self, text: &str) -> Result<String, BackendError> {
        let url = format!("{}/v1/chat/completions", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": text},
            ],
            "temperature": 0.3,
            "stream": false,
        });

        let response = ureq::post(&url)
            .timeout(self.timeout)
            .send_json(body)
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;

        let parsed: serde_json::Value = response
            .into_json()
            .map_err(|e| BackendError::Unavailable(e.to_string()))?;

        parse_completion(&parsed)
    }

    fn locality(&self) -> Locality {
        if url_is_local(&self.base_url) {
            Locality::Local
        } else {
            Locality::Online
        }
    }
}

/// True when the URL points at the user's own machine (localhost, loopback).
/// A `Local` backend is exempt from the disclaimer gate; anything else is
/// `Online` and must show the disclaimer first.
fn url_is_local(base_url: &str) -> bool {
    let after_scheme = base_url.split("://").nth(1).unwrap_or(base_url);
    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // Bracketed IPv6: take up to the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else {
        host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port)
    };
    let host = host.to_ascii_lowercase();
    host == "localhost"
        || host == "::1"
        || host.ends_with(".localhost")
        || host.starts_with("127.")
}

/// Extract the assistant message content from an OpenAI-compatible completion.
/// Pure and deterministic, so the parsing is tested without a socket.
fn parse_completion(parsed: &serde_json::Value) -> Result<String, BackendError> {
    let content = parsed["choices"][0]["message"]["content"]
        .as_str()
        .ok_or(BackendError::Empty)?;
    if content.trim().is_empty() {
        return Err(BackendError::Empty);
    }
    Ok(content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_completion() {
        let v = serde_json::json!({
            "choices": [{"message": {"content": "rewritten text"}}]
        });
        assert_eq!(parse_completion(&v).unwrap(), "rewritten text");
    }

    #[test]
    fn empty_or_missing_content_is_an_empty_error() {
        let missing = serde_json::json!({ "choices": [] });
        assert_eq!(parse_completion(&missing), Err(BackendError::Empty));
        let blank = serde_json::json!({
            "choices": [{"message": {"content": "   "}}]
        });
        assert_eq!(parse_completion(&blank), Err(BackendError::Empty));
    }

    #[test]
    fn locality_follows_the_url_host() {
        // Localhost / loopback servers are Local (no disclaimer).
        for local in [
            "http://localhost:11434",
            "http://127.0.0.1:1234",
            "http://[::1]:8080",
            "http://my-box.localhost/v1",
        ] {
            assert_eq!(
                HttpBackend::new(local, "m", "s").locality(),
                Locality::Local,
                "{local} should be local"
            );
        }
        // Any other host is Online (disclaimer required).
        for online in ["https://api.openai.com", "http://example.com:8080"] {
            assert_eq!(
                HttpBackend::new(online, "m", "s").locality(),
                Locality::Online,
                "{online} should be online"
            );
        }
    }
}
