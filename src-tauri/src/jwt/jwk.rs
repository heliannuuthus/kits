use anyhow::Context;
use jose_jwk::OkpCurves;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{JsonWebAlgorithm, JwkeyOperation, JwkeyType, JwkeyUsage};
use crate::{enums::RsaKeySize, errors::Result, utils::random_bytes};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwkGenerate {
    pub key_id: Option<String>,
    pub key_type: JwkeyType,
    pub algorithm: Option<JsonWebAlgorithm>,
    pub usage: Option<JwkeyUsage>,
    pub operations: Option<Vec<JwkeyOperation>>,
    pub bits: Option<RsaKeySize>,
}
#[tauri::command]
pub(crate) async fn generate_jwk(data: JwkGenerate) -> Result<String> {
    let mut value = generate_jwk_inner(
        data.algorithm.unwrap_or(data.key_type.default_algorithm()),
    )
    .await?;
    if let Some(key_id) = data.key_id {
        value["kid"] = serde_json::Value::String(key_id);
    }
    if let Some(alg) = data.algorithm {
        value["alg"] = json!(alg);
    }
    if let Some(ops) = data.operations
        && !ops.is_empty()
    {
        value["key_ops"] = json!(&ops);
    }
    if let Some(usage) = data.usage {
        value["use"] = serde_json::Value::String(usage.to_string())
    }

    Ok(serde_json::to_string_pretty(&value)
        .context("value to string failed")?)
}

pub(crate) async fn generate_jwk_inner(
    algorithm: crate::jwt::JsonWebAlgorithm,
) -> Result<serde_json::Value> {
    let mut rng = rand::thread_rng();

    let key = match algorithm {
        JsonWebAlgorithm::Dir
        | JsonWebAlgorithm::HS256
        | JsonWebAlgorithm::A128GCM
        | JsonWebAlgorithm::A128GCMKW
        | JsonWebAlgorithm::A128KW
        | JsonWebAlgorithm::A128cbcHs256 => {
            let key = random_bytes(32)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JsonWebAlgorithm::HS384
        | JsonWebAlgorithm::A192GCM
        | JsonWebAlgorithm::A192GCMKW
        | JsonWebAlgorithm::A192KW
        | JsonWebAlgorithm::A192cbcHs384 => {
            let key = random_bytes(48)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JsonWebAlgorithm::HS512
        | JsonWebAlgorithm::A256GCM
        | JsonWebAlgorithm::A256GCMKW
        | JsonWebAlgorithm::A256KW
        | JsonWebAlgorithm::A256cbcHs512 => {
            let key = random_bytes(64)?;
            jose_jwk::Key::Oct(jose_jwk::Oct { k: key.into() })
        }
        JsonWebAlgorithm::ES256 => {
            let secret_key =
                elliptic_curve::SecretKey::<p256::NistP256>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JsonWebAlgorithm::ES384 => {
            let secret_key =
                elliptic_curve::SecretKey::<p384::NistP384>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JsonWebAlgorithm::ES521 => {
            let secret_key =
                elliptic_curve::SecretKey::<p521::NistP521>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JsonWebAlgorithm::ES256K => {
            let secret_key =
                elliptic_curve::SecretKey::<k256::Secp256k1>::random(&mut rng);
            jose_jwk::Key::Ec(jose_jwk::Ec::from(secret_key))
        }
        JsonWebAlgorithm::RS256
        | JsonWebAlgorithm::PS256
        | JsonWebAlgorithm::RS384
        | JsonWebAlgorithm::PS384
        | JsonWebAlgorithm::RS512
        | JsonWebAlgorithm::PS512
        | JsonWebAlgorithm::Rsa1_5
        | JsonWebAlgorithm::RsaOaep
        | JsonWebAlgorithm::RsaOaep256
        | JsonWebAlgorithm::RsaOaep384
        | JsonWebAlgorithm::RsaOaep521 => {
            let private_key =
                RsaPrivateKey::new(&mut rng, RsaKeySize::Rsa2048 as usize)
                    .context("generate rsa 2048 key failed")?;
            jose_jwk::Key::Rsa(jose_jwk::Rsa::from(private_key))
        }

        JsonWebAlgorithm::EdDSA => {
            let ed = ed25519_dalek::SigningKey::generate(&mut rng);
            let ed_verify_key = ed.verifying_key();
            jose_jwk::Key::Okp(jose_jwk::Okp {
                crv: OkpCurves::Ed25519,
                x: ed_verify_key.to_bytes().to_vec().into(),
                d: Some(ed.as_bytes().to_vec().into()),
            })
        }
        JsonWebAlgorithm::EcdhEs
        | JsonWebAlgorithm::EcdhEsA128kw
        | JsonWebAlgorithm::EcdhEsA192kw
        | JsonWebAlgorithm::EcdhEsA256kw => {
            let x25519_key =
                x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            let x25519_pub_key = x25519_dalek::PublicKey::from(&x25519_key);
            jose_jwk::Key::Okp(jose_jwk::Okp {
                crv: OkpCurves::X25519,
                x: x25519_pub_key.as_bytes().to_vec().into(),
                d: Some(x25519_key.as_bytes().to_vec().into()),
            })
        }
    };
    Ok(serde_json::to_value(&key).context("serilize jwk failed")?)
}

#[cfg(test)]
mod test {
    use num_bigint::BigInt;
    use strum::IntoEnumIterator;
    use tracing::info;
    use tracing_test::traced_test;

    use super::JsonWebAlgorithm;
    use crate::{
        enums::RsaKeySize,
        jwt::{
            jwk::{generate_jwk, JwkGenerate},
            JwkeyOperation, JwkeyType,
        },
        utils::random_bytes,
    };

    #[tokio::test]
    #[traced_test]
    async fn test_generate_jwk() {
        let ops = JwkeyOperation::iter().collect::<Vec<JwkeyOperation>>();
        for kty in JwkeyType::iter() {
            for alg in JsonWebAlgorithm::iter() {
                let mut bits = None;
                if alg.eq(&JsonWebAlgorithm::RS256) {
                    bits = Some(RsaKeySize::Rsa2048);
                } else if alg.eq(&JsonWebAlgorithm::RS384) {
                    bits = Some(RsaKeySize::Rsa3072);
                } else if alg.eq(&JsonWebAlgorithm::RS512) {
                    bits = Some(RsaKeySize::Rsa4096);
                }
                info!(
                    "{}",
                    generate_jwk(JwkGenerate {
                        key_id: None,
                        key_type: kty,
                        algorithm: Some(alg),
                        usage: None,
                        operations: Some(ops.clone()),
                        bits,
                    })
                    .await
                    .unwrap()
                )
            }
        }
    }
    #[tokio::test]
    #[traced_test]
    async fn test_generate_kid() {
        let random_bytes = random_bytes(16).unwrap();
        let b_int =
            BigInt::from_bytes_be(num_bigint::Sign::Plus, &random_bytes);
        info!("output: {}", b_int.to_str_radix(36));
    }
}
