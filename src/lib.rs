mod config;
mod validator;

// Re-export main types for user convenience
pub use config::OidcConfig;
pub use validator::OidcValidator;

// Re-export jsonwebtoken types that users will need
pub use jsonwebtoken::{Algorithm, Validation};
