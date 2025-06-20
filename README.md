# async-oidc-jwt-validator

[![Crates.io](https://img.shields.io/crates/v/async-oidc-jwt-validator.svg)](https://crates.io/crates/async-oidc-jwt-validator)
[![Docs.rs](https://docs.rs/async-oidc-jwt-validator/badge.svg)](https://docs.rs/async-oidc-jwt-validator)
[![CI](https://github.com/soya-miyoshi/async-oidc-jwt-validator/workflows/CI/badge.svg)](https://github.com/soya-miyoshi/async-oidc-jwt-validator/actions)
[![Rust GitHub Template](https://img.shields.io/badge/Rust%20GitHub-Template-blue)](https://rust-github.github.io/)

A fast, secure, and easy-to-use Rust crate for validating OpenID Connect (OIDC) JWTs.

This library provides a simple way to protect your backend services by verifying tokens from providers like Keycloak, Auth0, or Okta. It handles the complexities of fetching, caching, and refreshing JSON Web Keys (JWKS) automatically.

## Features

- Built with `async/await` from the ground up to be non-blocking and highly performant. Perfect for Axum, Actix Web, Tonic, and any modern Rust web service.

- Caches JSON Web Key Sets (JWKS) in memory to eliminate latency from repeated fetch(). The cache is thread-safe (`Arc<RwLock>`). Ready for highly concurrent applications.

- Just provide your provider's issuer URL, and the library discovers the correct JWKS endpoint using the standard OIDC Discovery (`/.well-known/openid-configuration`), saving you from hardcoding URLs.

- Comes with a simple `validate()` method that enforces standard OIDC security checks (issuer, audience, signature, expiration) out-of-the-box. 

- Works seamlessly with Keycloak, Auth0, Okta, Google, and any other OpenID Connect compliant identity provider.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
async-oidc-jwt-validator = "0.1.2"
```

## Usage

### Quick Start

```rust
use async_oidc_jwt_validator::{OidcValidator, OidcConfig, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
struct MyClaims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub aud: serde_json::Value,
    pub iss: String,
    // Add your custom fields here
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // OIDC configuration with automatic discovery
    let config = OidcConfig::new_with_discovery(
        "https://your-oidc-provider.com".to_string(),
        "your-client-id".to_string()
    ).await?;
    let validator = OidcValidator::new(config);
    
    let token = "your-jwt-token-here";
    
    // Simple validation with default settings
    match validator.validate::<MyClaims>(token).await {
        Ok(claims) => println!("Valid token for user: {}", claims.sub),
        Err(e) => println!("Invalid token: {}", e),
    }
    
    Ok(())
}
```

### Manual JWKS Configuration

If you prefer to manually specify the JWKS URI:

```rust
let config = OidcConfig::new(
    "https://your-oidc-provider.com".to_string(),
    "your-client-id".to_string(),
    "https://your-oidc-provider.com/.well-known/jwks.json".to_string()
);
let validator = OidcValidator::new(config);
```

### Custom Validation

For more control over the validation process:

```rust
let mut validation = Validation::new(Algorithm::RS256);
validation.set_issuer(&["https://your-oidc-provider.com"]);
validation.set_audience(&["your-client-id"]);

match validator.validate_custom::<MyClaims>(token, &validation).await {
    Ok(claims) => println!("Valid token for user: {}", claims.sub),
    Err(e) => println!("Invalid token: {}", e),
}
```
## License

Licensed under MIT license

## Contribution

See [CONTRIBUTING.md](CONTRIBUTING.md).
