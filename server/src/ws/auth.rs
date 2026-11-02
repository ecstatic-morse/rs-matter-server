//! The optional bearer token on the WebSocket endpoint.
//!
//! The protocol has no authentication of its own: any client that can reach
//! the port can commission, remove and control every device on the fabric.
//! That is how the reference server behaves, and it is fine on loopback or a
//! Unix socket, but not on a port other hosts can reach. A configured token
//! makes every upgrade request carry `Authorization: Bearer <token>`; one that
//! does not is answered `401` and never upgraded.
//!
//! Only the upgrade is guarded. `/health` stays open, because the container
//! health check has nothing to authenticate with and the endpoint reveals no
//! more than a node count. The OTA upload endpoint needs an upload id that
//! only an authenticated connection can obtain.

use std::path::Path;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::http::RequestHead;

/// A configured token.
///
/// Held as its SHA-256 digest, so a comparison takes the same time whatever
/// the length of the candidate — comparing the raw bytes in constant time
/// still returns early on a length mismatch. `Debug` never prints it.
#[derive(Clone)]
pub struct AuthToken {
    digest: [u8; 32],
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthToken(<redacted>)")
    }
}

impl AuthToken {
    /// A token from its text, with surrounding whitespace removed. An empty
    /// token is refused: accepting it would look configured and authenticate
    /// nothing.
    pub fn new(token: &str) -> Result<Self> {
        let token = token.trim();
        if token.is_empty() {
            bail!("the WebSocket token is empty");
        }
        Ok(Self {
            digest: Sha256::digest(token.as_bytes()).into(),
        })
    }

    /// Whether `candidate` is this token, compared in constant time.
    pub fn matches(&self, candidate: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(candidate.as_bytes()).into();
        self.digest.ct_eq(&digest).into()
    }

    /// Whether a request carries this token as `Authorization: Bearer <token>`.
    ///
    /// The scheme is matched without regard to case, as RFC 7235 has it.
    pub fn authorizes(&self, head: &RequestHead) -> bool {
        let Some(value) = head.header("authorization") else {
            return false;
        };
        let Some((scheme, credentials)) = value.trim().split_once(' ') else {
            return false;
        };
        scheme.eq_ignore_ascii_case("bearer") && self.matches(credentials.trim())
    }
}

/// Resolve the configured token: `file` (its contents, trimmed) when given,
/// else `value`, else none at all.
pub fn load(file: Option<&Path>, value: Option<&str>) -> Result<Option<AuthToken>> {
    if let Some(file) = file {
        let contents = std::fs::read_to_string(file)
            .with_context(|| format!("reading WS_AUTH_TOKEN_FILE '{}'", file.display()))?;
        return AuthToken::new(&contents)
            .map(Some)
            .with_context(|| format!("WS_AUTH_TOKEN_FILE '{}'", file.display()));
    }
    match value {
        Some(value) => AuthToken::new(value).map(Some).context("WS_AUTH_TOKEN"),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::http::parse_head;

    fn upgrade(authorization: Option<&str>) -> RequestHead {
        let mut raw = String::from("GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n");
        if let Some(value) = authorization {
            raw.push_str(&format!("Authorization: {}\r\n", value));
        }
        raw.push_str("\r\n");
        parse_head(raw.as_bytes()).unwrap()
    }

    #[test]
    fn the_right_bearer_token_is_accepted() {
        let token = AuthToken::new("s3cret").unwrap();
        assert!(token.authorizes(&upgrade(Some("Bearer s3cret"))));
        assert!(token.authorizes(&upgrade(Some("bearer s3cret"))));
    }

    #[test]
    fn anything_else_is_refused() {
        let token = AuthToken::new("s3cret").unwrap();
        for authorization in [
            None,
            Some("Bearer"),
            Some("Bearer wrong"),
            Some("Bearer s3cret2"),
            Some("Bearer s3cre"),
            Some("Basic s3cret"),
            Some("s3cret"),
        ] {
            assert!(
                !token.authorizes(&upgrade(authorization)),
                "{:?} was accepted",
                authorization
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_the_token() {
        let token = AuthToken::new("  s3cret\n").unwrap();
        assert!(token.matches("s3cret"));
        assert!(AuthToken::new(" \n").is_err());
    }

    #[test]
    fn the_file_takes_precedence_over_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "from-file\n").unwrap();

        let token = load(Some(&path), Some("from-env")).unwrap().unwrap();
        assert!(token.matches("from-file"));
        assert!(!token.matches("from-env"));

        let token = load(None, Some("from-env")).unwrap().unwrap();
        assert!(token.matches("from-env"));

        assert!(load(None, None).unwrap().is_none());
        assert!(load(Some(&dir.path().join("missing")), Some("x")).is_err());
    }

    #[test]
    fn debug_does_not_print_the_token() {
        let token = AuthToken::new("s3cret").unwrap();
        assert!(!format!("{:?}", token).contains("s3cret"));
    }
}
