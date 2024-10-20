use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

use super::{
    enums::{
        Digest, EccCurveName, EciesEncryptionAlgorithm, EdwardsCurveName, Kdf,
        RsaEncryptionPadding,
    },
    errors::Result,
};
use crate::{
    enums::RsaKeySize,
    jwt::{JsonWebAlgorithm, JwkeyOperation, JwkeyType, JwkeyUsage},
};
#[derive(Serialize, Deserialize)]
pub struct KeyTuple(pub Option<String>, pub Option<String>);

impl KeyTuple {
    pub fn new(private_key: String, public_key: String) -> Self {
        KeyTuple(Some(private_key), Some(public_key))
    }

    pub fn empty() -> Self {
        KeyTuple(None, None)
    }

    pub fn private(&mut self, key: Option<String>) -> &mut Self {
        self.0 = key;
        self
    }

    pub fn public(&mut self, key: Option<String>) -> &mut Self {
        self.1 = key;
        self
    }
}

#[tauri::command]
pub fn random_bytes(size: usize) -> Result<Vec<u8>> {
    Ok(rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(size)
        .collect())
}

#[tauri::command]
pub fn random_id() -> Result<String> {
    let base = random_bytes(20)?;
    let base_int =
        num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &base);
    Ok(base_int.to_str_radix(36))
}

#[tauri::command]
pub fn elliptic_curve() -> Vec<EccCurveName> {
    EccCurveName::iter().collect::<Vec<EccCurveName>>()
}

#[tauri::command]
pub fn edwards() -> Vec<EdwardsCurveName> {
    EdwardsCurveName::iter().collect::<Vec<EdwardsCurveName>>()
}

#[tauri::command]
pub fn kdfs() -> Vec<Kdf> {
    Kdf::iter().collect::<Vec<Kdf>>()
}

#[tauri::command]
pub fn digests() -> Vec<Digest> {
    Digest::iter().collect::<Vec<Digest>>()
}

#[tauri::command]
pub fn ecies_enc_alg() -> Vec<EciesEncryptionAlgorithm> {
    EciesEncryptionAlgorithm::iter().collect::<Vec<EciesEncryptionAlgorithm>>()
}

#[tauri::command]
pub fn rsa_key_size() -> Vec<RsaKeySize> {
    RsaKeySize::iter().collect::<Vec<RsaKeySize>>()
}

#[tauri::command]
pub fn rsa_encryption_padding() -> Vec<RsaEncryptionPadding> {
    RsaEncryptionPadding::iter().collect::<Vec<RsaEncryptionPadding>>()
}

#[tauri::command]
pub(crate) fn jwkey_algorithm(kty: JwkeyType) -> Vec<JsonWebAlgorithm> {
    match kty {
        JwkeyType::RSA => vec![
            JsonWebAlgorithm::RS256,
            JsonWebAlgorithm::RS384,
            JsonWebAlgorithm::RS512,
            JsonWebAlgorithm::PS256,
            JsonWebAlgorithm::PS384,
            JsonWebAlgorithm::PS512,
        ],
        JwkeyType::EcDSA => vec![
            JsonWebAlgorithm::ES256,
            JsonWebAlgorithm::ES384,
            JsonWebAlgorithm::ES521,
            JsonWebAlgorithm::ES256K,
        ],
        JwkeyType::Ed25519 => vec![JsonWebAlgorithm::EdDSA],
        JwkeyType::X25519 => vec![
            JsonWebAlgorithm::EcdhEs,
            JsonWebAlgorithm::EcdhEsA128kw,
            JsonWebAlgorithm::EcdhEsA192kw,
            JsonWebAlgorithm::EcdhEsA256kw,
        ],
        JwkeyType::Symmetric => vec![
            JsonWebAlgorithm::Dir,
            JsonWebAlgorithm::HS256,
            JsonWebAlgorithm::A128GCM,
            JsonWebAlgorithm::A128GCMKW,
            JsonWebAlgorithm::A128KW,
            JsonWebAlgorithm::A128cbcHs256,
            JsonWebAlgorithm::HS384,
            JsonWebAlgorithm::A192GCM,
            JsonWebAlgorithm::A192GCMKW,
            JsonWebAlgorithm::A192KW,
            JsonWebAlgorithm::A192cbcHs384,
            JsonWebAlgorithm::HS512,
            JsonWebAlgorithm::A256GCM,
            JsonWebAlgorithm::A256GCMKW,
            JsonWebAlgorithm::A256KW,
            JsonWebAlgorithm::A256cbcHs512,
        ],
    }
}

#[tauri::command]
pub(crate) fn jwkey_usage(kty: JwkeyType) -> Vec<JwkeyUsage> {
    match kty {
        JwkeyType::RSA => vec![JwkeyUsage::Encryption, JwkeyUsage::Signature],
        JwkeyType::EcDSA => vec![JwkeyUsage::Signature],
        JwkeyType::Ed25519 => vec![JwkeyUsage::Signature],
        JwkeyType::X25519 => vec![JwkeyUsage::Encryption],
        JwkeyType::Symmetric => {
            vec![JwkeyUsage::Encryption, JwkeyUsage::Signature]
        }
    }
}

#[tauri::command]
pub async fn jwkey_type() -> Vec<JwkeyType> {
    JwkeyType::iter().collect::<Vec<JwkeyType>>()
}

#[tauri::command]
pub async fn jwkey_operation() -> Vec<JwkeyOperation> {
    JwkeyOperation::iter().collect::<Vec<JwkeyOperation>>()
}
