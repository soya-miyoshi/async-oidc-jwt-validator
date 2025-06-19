//! # async-oidc-jwt-validator
//!
//! An asynchronous OIDC JWT validator with JWKS caching for Keycloak and other OIDC providers.
//!
//! ## Example
//!
//! ```no_run
//! use async_oidc_jwt_validator::{OidcValidator, OidcConfig, Validation, Algorithm};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Debug, Deserialize, Serialize)]
//! struct MyClaims {
//!     pub sub: String,
//!     pub exp: usize,
//!     pub iat: usize,
//!     pub aud: serde_json::Value,
//!     pub iss: String,
//!     // Add your custom fields here
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // OIDC configuration with automatic discovery
//!     let config = OidcConfig::new_with_discovery(
//!         "https://your-oidc-provider.com".to_string(),
//!         "your-client-id".to_string()
//!     ).await?;
//!     let validator = OidcValidator::new(config);
//!     
//!     // Or manually specify JWKS URI:
//!     // let config = OidcConfig::new(
//!     //     "https://your-oidc-provider.com".to_string(),
//!     //     "your-client-id".to_string(),
//!     //     "https://your-oidc-provider.com/.well-known/jwks.json".to_string()
//!     // );
//!     // let validator = OidcValidator::new(config);
//!     
//!     let token = "your-jwt-token-here";
//!     
//!     // Simple validation with default settings
//!     match validator.validate::<MyClaims>(token).await {
//!         Ok(claims) => println!("Valid token for user: {}", claims.sub),
//!         Err(e) => println!("Invalid token: {}", e),
//!     }
//!     
//!     // Or custom validation
//!     let mut validation = Validation::new(Algorithm::RS256);
//!     validation.set_issuer(&["https://your-oidc-provider.com"]);
//!     validation.set_audience(&["your-client-id"]);
//!     
//!     match validator.validate_custom::<MyClaims>(token, &validation).await {
//!         Ok(claims) => println!("Valid token for user: {}", claims.sub),
//!         Err(e) => println!("Invalid token: {}", e),
//!     }
//!     
//!     Ok(())
//! }
//! ```

use jsonwebtoken::errors::{Error as JwtError, ErrorKind, Result as JwtResult};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, DecodingKey};
use serde::Deserialize;
use std::collections::HashMap;

// Re-export for user convenience
pub use jsonwebtoken::{Algorithm, Validation};

/// OpenID Connect Discovery document structure
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    issuer: String,
    jwks_uri: String,
}

/// Configuration for OIDC authentication
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub jwks_uri: String,
}

/// OIDC JWT validator with JWKS caching
#[derive(Clone)]
pub struct OidcValidator {
    config: OidcConfig,
    jwks_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Jwk>>>,
}

impl OidcConfig {
    /// Creates a new OidcConfig with custom parameters
    pub fn new(issuer_url: String, client_id: String, jwks_uri: String) -> Self {
        Self {
            issuer_url,
            client_id,
            jwks_uri: jwks_uri,
        }
    }

    pub async fn new_with_discovery(issuer_url: String, client_id: String) -> JwtResult<Self> {
        let jwks_uri = Self::discover_jwks_uri(&issuer_url).await?;
        Ok(Self {
            issuer_url,
            client_id,
            jwks_uri: jwks_uri,
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

        if discovery.issuer != issuer_url {
            return Err(JwtError::from(ErrorKind::InvalidIssuer));
        }

        log::debug!("Discovered JWKS URI: {}", discovery.jwks_uri);
        Ok(discovery.jwks_uri)
    }
}

impl OidcValidator {
    /// Creates a new OidcValidator with the given configuration
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            jwks_cache: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    async fn fetch_jwks(&self) -> JwtResult<JwkSet> {
        let jwks_url = self.config.jwks_uri.clone();

        log::debug!("Fetching JWKS from: {}", jwks_url);

        let response = reqwest::get(&jwks_url).await.map_err(|e| {
            JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "Failed to fetch JWKS: {}",
                e
            )))
        })?;

        if !response.status().is_success() {
            return Err(JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "JWKS request failed with status: {}",
                response.status()
            ))));
        }

        let jwks: JwkSet = response.json().await.map_err(|e| {
            JwtError::from(ErrorKind::InvalidRsaKey(format!(
                "Failed to parse JWKS response: {}",
                e
            )))
        })?;

        log::debug!("Fetched {} keys from JWKS", jwks.keys.len());
        Ok(jwks)
    }

    async fn get_jwk(&self, kid: &str) -> JwtResult<Jwk> {
        // Check cache first
        {
            let cache = self.jwks_cache.read().await;
            if let Some(jwk) = cache.get(kid) {
                return Ok(jwk.clone());
            }
        }

        // If not found, refresh cache and try again
        self.refresh_jwks_cache().await?;

        let cache = self.jwks_cache.read().await;
        cache
            .get(kid)
            .cloned()
            .ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))
    }

    pub async fn validate_custom<T>(&self, token: &str, validation: &Validation) -> JwtResult<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        log::debug!("Verifying JWT token");

        // Decode header to get kid
        let header = jsonwebtoken::decode_header(token)?;

        let kid = header
            .kid
            .ok_or_else(|| JwtError::from(ErrorKind::InvalidToken))?;
        log::debug!("Token kid: {}", kid);

        // Get JWK for this kid (will refresh cache if not found)
        let jwk = self.get_jwk(&kid).await?;

        log::debug!("Found matching key with kid: {}", kid);

        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|_e| JwtError::from(ErrorKind::InvalidKeyFormat))?;

        // Decode and validate token
        let token_data = decode::<T>(token, &decoding_key, &validation)?;

        log::debug!("Token verified successfully");
        Ok(token_data.claims)
    }

    pub async fn validate<T>(&self, token: &str) -> JwtResult<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        log::debug!("Validating JWT token with minimal validation");

        // Create a minimal validation configuration
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer_url]);
        validation.set_audience(&[&self.config.client_id]);

        self.validate_custom(token, &validation).await
    }

    /// Refreshes the JWKS cache by fetching the latest keys
    pub async fn refresh_jwks_cache(&self) -> JwtResult<()> {
        log::info!("Refreshing JWKS cache");
        let new_jwks = self.fetch_jwks().await?;

        // Check if an update is needed using a read lock
        let needs_update = {
            let cache = self.jwks_cache.read().await;

            // Condition 1: The number of keys is different.
            let lengths_are_different = new_jwks.keys.len() != cache.len();

            // Condition 2: There is at least one new key that wasn't in the old cache.
            // This only needs to run if the lengths are the same.
            let has_added_keys = if lengths_are_different {
                false // No need to run this check if we already know we need an update.
            } else {
                new_jwks.keys.iter().any(|jwk| {
                    if let Some(kid) = &jwk.common.key_id {
                        !cache.contains_key(kid)
                    } else {
                        false // Skip keys without kid
                    }
                })
            };
            lengths_are_different || has_added_keys
        }; // Read lock released here

        // Only acquire write lock if there are new keys
        if needs_update {
            log::info!("New keys detected, replacing entire cache");

            // Build new HashMap from fetched JWKS
            let mut new_cache = HashMap::new();
            for jwk in new_jwks.keys {
                if let Some(kid) = jwk.common.key_id.clone() {
                    log::debug!("Adding key to new cache: {}", kid);
                    new_cache.insert(kid, jwk);
                }
            }

            // Replace entire cache
            let mut cache = self.jwks_cache.write().await;
            *cache = new_cache;

            log::info!("Successfully replaced JWKS cache with {} keys", cache.len());
        } else {
            log::debug!("No new keys found in JWKS, cache unchanged");
        }

        Ok(())
    }
}
