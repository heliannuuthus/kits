use anyhow::Context;

use super::JsonWebAlgorithm;
use crate::errors::{Error, Result};

#[tauri::command]
pub(crate) fn generate_jws(
    header: String,
    payload: String,
    secret: String,
    jwa: JsonWebAlgorithm,
) -> Result<String> {
    let jwk_type = jwa.to_type();
    let algorithm: jose_jwa::Signing = jwa.try_into()?;
    let header = serde_json::from_str(&header).context("invalid header")?;
    let payload = serde_json::from_str(&payload).context("invalid payload")?;
    let secret = serde_json::from_str(&secret).context("invalid secret")?;

    match jwk_type {
        super::JwkeyType::RSA => {
            
        },
        super::JwkeyType::EcDSA => jose_jwk::Ec::from(secret),
        super::JwkeyType::Symmetric => jose_jwk::Oct::from(secret),

        _ => {
            return Err(Error::Unsupported(format!("jwk type {:?}", jwk_type)))
        }
    };

    Ok("".to_string())
}
