use crate::config::OidcConfig;
use jsonwebtoken::errors::{Error as JwtError, ErrorKind, Result as JwtResult};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::HashMap;

/// OIDC JWT validator with JWKS caching
#[derive(Clone)]
pub struct OidcValidator {
    config: OidcConfig,
    jwks_cache: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Jwk>>>,
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
        let token_data = decode::<T>(token, &decoding_key, validation)?;

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
