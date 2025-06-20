use jsonwebtoken::errors::{Error as JwtError, ErrorKind, Result as JwtResult};
use serde::Deserialize;

/// OpenID Connect Discovery document structure
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// Configuration for OIDC authentication
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub jwks_uri: String,
}

impl OidcConfig {
    /// Creates a new OidcConfig with custom parameters
    pub fn new(issuer_url: String, client_id: String, jwks_uri: String) -> Self {
        Self {
            issuer_url,
            client_id,
            jwks_uri,
        }
    }

    pub async fn new_with_discovery(issuer_url: String, client_id: String) -> JwtResult<Self> {
        let jwks_uri = Self::discover_jwks_uri(&issuer_url).await?;
        Ok(Self {
            issuer_url,
            client_id,
            jwks_uri,
        })
    }

    async fn discover_jwks_uri(issuer_url: &str) -> JwtResult<String> {
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer_url);

        log::debug!("Fetching OpenID Connect Discovery from: {}", discovery_url);

        let response = reqwest::get(&discovery_url).await.map_err(|e| {
            JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "Failed to fetch OIDC discovery document: {}",
                e
            )))
        })?;

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        if !content_type.starts_with("application/json") {
            return Err(JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "Unexpected Content-Type: '{}', expected 'application/json'",
                content_type
            ))));
        }

        if !response.status().is_success() {
            return Err(JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "OIDC discovery request failed with status: {}",
                response.status()
            ))));
        }

        let discovery: OidcDiscovery = response.json().await.map_err(|e| {
            JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "Failed to parse OIDC discovery response: {}",
                e
            )))
        })?;

        log::debug!("Discovered JWKS URI: {}", discovery.jwks_uri);
        Ok(discovery.jwks_uri)
    }
}
