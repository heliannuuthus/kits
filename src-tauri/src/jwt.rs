use std::fmt::Display;

use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::errors::{Error, Result};

pub mod jwe;
pub mod jwk;
pub mod jws;

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "lowercase")]
pub enum JwkeyType {
    RSA,
    EcDSA,
    Ed25519,
    X25519,
    Symmetric,
}

impl JwkeyType {
    pub fn default_algorithm(self) -> JsonWebAlgorithm {
        match self {
            JwkeyType::RSA => JsonWebAlgorithm::RS256,
            JwkeyType::EcDSA => JsonWebAlgorithm::ES256,
            JwkeyType::Ed25519 => JsonWebAlgorithm::EdDSA,
            JwkeyType::X25519 => JsonWebAlgorithm::EcdhEs,
            JwkeyType::Symmetric => JsonWebAlgorithm::A256GCM,
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum JsonWebAlgorithm {
    #[serde(rename = "dir")]
    Dir,
    A128KW,
    A192KW,
    A256KW,
    A128GCM,
    A192GCM,
    A256GCM,
    A128GCMKW,
    A192GCMKW,
    A256GCMKW,
    #[serde(rename = "A128CBC-HS256")]
    A128cbcHs256,
    #[serde(rename = "A192CBC-HS384")]
    A192cbcHs384,
    #[serde(rename = "A256CBC-HS512")]
    A256cbcHs512,
    HS256,
    HS384,
    HS512,

    ES256,
    ES384,
    ES521,
    ES256K,

    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    #[serde(rename = "RSA1_5")]
    Rsa1_5,
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    #[serde(rename = "RSA-OAEP-384")]
    RsaOaep384,
    #[serde(rename = "RSA-OAEP-512")]
    RsaOaep521,

    EdDSA,
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128kw,
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192kw,
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256kw,
}

impl JsonWebAlgorithm {
    pub fn to_type(&self) -> JwkeyType {
     match self {
            JsonWebAlgorithm::Dir
            | JsonWebAlgorithm::A128KW
            | JsonWebAlgorithm::A192KW
            | JsonWebAlgorithm::A256KW
            | JsonWebAlgorithm::A128GCM
            | JsonWebAlgorithm::A192GCM
            | JsonWebAlgorithm::A256GCM
            | JsonWebAlgorithm::A128GCMKW
            | JsonWebAlgorithm::A192GCMKW
            | JsonWebAlgorithm::A256GCMKW
            | JsonWebAlgorithm::A128cbcHs256
            | JsonWebAlgorithm::A192cbcHs384
            | JsonWebAlgorithm::A256cbcHs512
            | JsonWebAlgorithm::HS256
            | JsonWebAlgorithm::HS384
            | JsonWebAlgorithm::HS512 => JwkeyType::Symmetric,
            JsonWebAlgorithm::ES256
            | JsonWebAlgorithm::ES384
            | JsonWebAlgorithm::ES521
            | JsonWebAlgorithm::ES256K
            | JsonWebAlgorithm::EdDSA
            | JsonWebAlgorithm::EcdhEs
            | JsonWebAlgorithm::EcdhEsA128kw
            | JsonWebAlgorithm::EcdhEsA192kw
            | JsonWebAlgorithm::EcdhEsA256kw => JwkeyType::EcDSA,
            JsonWebAlgorithm::RS256
            | JsonWebAlgorithm::RS384
            | JsonWebAlgorithm::RS512
            | JsonWebAlgorithm::PS256
            | JsonWebAlgorithm::PS384
            | JsonWebAlgorithm::PS512
            | JsonWebAlgorithm::Rsa1_5
            | JsonWebAlgorithm::RsaOaep
            | JsonWebAlgorithm::RsaOaep256
            | JsonWebAlgorithm::RsaOaep384
            | JsonWebAlgorithm::RsaOaep521 => JwkeyType::RSA,
        }
    }
}
impl TryInto<jose_jwa::Signing> for JsonWebAlgorithm {
    type Error = Error;

    fn try_into(self) -> std::result::Result<jose_jwa::Signing, Self::Error> {
        Ok(match self {
            JsonWebAlgorithm::EdDSA => jose_jwa::Signing::EdDsa,
            JsonWebAlgorithm::ES256 => jose_jwa::Signing::Es256,
            JsonWebAlgorithm::ES256K => jose_jwa::Signing::Es256K,
            JsonWebAlgorithm::ES384 => jose_jwa::Signing::Es384,
            JsonWebAlgorithm::ES521 => jose_jwa::Signing::Es512,
            JsonWebAlgorithm::HS256 => jose_jwa::Signing::Hs256,
            JsonWebAlgorithm::HS384 => jose_jwa::Signing::Hs384,
            JsonWebAlgorithm::HS512 => jose_jwa::Signing::Hs512,
            JsonWebAlgorithm::PS256 => jose_jwa::Signing::Ps256,
            JsonWebAlgorithm::PS384 => jose_jwa::Signing::Ps384,
            JsonWebAlgorithm::PS512 => jose_jwa::Signing::Ps512,
            JsonWebAlgorithm::RS256 => jose_jwa::Signing::Rs256,
            JsonWebAlgorithm::RS384 => jose_jwa::Signing::Rs384,
            JsonWebAlgorithm::RS512 => jose_jwa::Signing::Rs512,
            JsonWebAlgorithm::Dir => jose_jwa::Signing::Null,
            _ => return Err(Error::Unsupported(format!("{:?}", self))),
        })
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum JwkeyUsage {
    #[serde(rename = "Encryption")]
    Encryption,
    #[serde(rename = "Signature")]
    Signature,
}

impl Display for JwkeyUsage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            JwkeyUsage::Encryption => "enc",
            JwkeyUsage::Signature => "sig",
        };

        write!(f, "{}", str)
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "camelCase")]
pub enum JwkeyOperation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
}
